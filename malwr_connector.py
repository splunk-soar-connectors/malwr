# --
# File: malwr_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
from phantom.vault import Vault
import os
import sys

from malwr_consts import *

# Other imports used by this connector
import requests
import time
from bs4 import BeautifulSoup

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'apimalwr'))
from MalwrAPI import MalwrAPI  # noqa  # pylint:disable=E0401

requests.packages.urllib3.disable_warnings()


class MalwrConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "detonate_file"
    ACTION_ID_GET_STATUS = "get_status"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'

    def __init__(self):

        # Call the BaseConnectors init first
        super(MalwrConnector, self).__init__()

        self._malwr_conn = None

    def _get_status(self, param):

        action_result = self.add_action_result(ActionResult(param))

        task_id = param[MALWR_JSON_TASK_ID]

        data = {}
        data[MALWR_JSON_TASK_ID] = task_id

        ret_val, status = self._poll_task_status(task_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (status):
            action_result.add_data(data)
            result_url = "{0}{1}".format(MALWR_BASE_URL, MALWR_ANALYSIS_URI.format(task_id))
            data[MALWR_JSON_RESULT_URL] = result_url
            data[MALWR_JSON_STATUS] = "processed"
            self._get_av_detections(result_url, data, action_result)
            return action_result.set_status(phantom.APP_SUCCESS, MALWR_DET_REPORT.format(result_url))

        result_url = "{0}{1}".format(MALWR_BASE_URL, MALWR_ANALYSIS_URI.format(task_id))
        data[MALWR_JSON_RESULT_URL] = result_url
        data[MALWR_JSON_STATUS] = "pending"
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS, "Detonation process still ongoing. Please re-try after sometime")

    def _test_connectivity(self, param):

        ret_val = self._login_to_malwr()

        if (phantom.is_fail(ret_val)):
            self.append_to_message("Test Connectivity Failed")
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, "Test Connectivity Passed")

    def _login_to_malwr(self, action_result=None):

        self.save_progress('Logging into Malwr')

        config = self.get_config()

        if (action_result is None):
            action_result = self.add_action_result(ActionResult())

        try:
            self._malwr_conn = MalwrAPI(verbose=True, username=config[MALWR_JSON_USERNAME], password=config[MALWR_JSON_PASSWORD])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to login to malwr", e)

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, files, data, action_result):

        config = self.get_config()

        data.update({'api_key': config[MALWR_JSON_API_KEY]})

        url = "{0}{1}".format(config[MALWR_JSON_BASE_URL], endpoint)

        try:
            r = requests.post(url, files=files, data=data)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, MALWR_ERR_SERVER_CONNECTION, e), None)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (action_result.set_status(phantom.APP_ERROR, MALWR_ERR_FROM_SERVER, status=r.status_code, detail=r.text), None)

        try:
            resp_json = r.json()
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, MALWR_ERR_JSON_PARSE, data=r.text), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _get_shared_value(self, param):

        private = param.get(MALWR_JSON_PRIVATE, True)

        return 'yes' if (not private) else 'no'

    def _parse_status_response(self, status_resp, action_result, task_id):

        try:
            soup = BeautifulSoup(status_resp.content)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse status polling response", e), None)

        analysis = soup.find_all(href='/analysis/{0}/'.format(task_id))

        return (phantom.APP_SUCCESS, analysis)

    def _poll_task_status(self, task_id, action_result, status_link=None):

        if (status_link is None):
            status_link = "/submission/status/{0}".format(task_id)

        polling_attempt = 0
        max_polling_attempts = 5
        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) " +
                          "Gecko/20100101 Firefox/41.0"
        }

        req_sess = requests.Session()

        status = []

        while True:

            polling_attempt += 1

            self.save_progress("Polling attempt {0} of {1}".format(polling_attempt, max_polling_attempts))

            try:
                status_resp = req_sess.get("{0}{1}".format(MALWR_BASE_URL, status_link), headers=headers)
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR, "Unable to connect to malwr.com", e), None)

            if (not status_resp):
                return (action_result.set_status(phantom.APP_ERROR, MALWR_ERR_DATA_FROM_SERVER, message=status_resp), None)

            ret_val, status = self._parse_status_response(status_resp, action_result, task_id)

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status(), None)

            if (status):
                break

            if (polling_attempt == max_polling_attempts):
                self.save_progress("Reached max polling attempts.")
                break

            time.sleep(MALWR_SLEEP_SECS)

        return (phantom.APP_SUCCESS, status)

    def _parse_av_table_response(self, resp, action_result):

        av_results = []

        try:
            soup = BeautifulSoup(resp.content, "html.parser")
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Unable to parse status polling response", e)
            return av_results

        # is the column data a table
        sav = soup.find(id='static_antivirus')

        av_table = sav.find('table', recursive=False)

        if (not av_table):
            return []

        header_cols = av_table.find_all('th')

        if (not header_cols):
            return []

        keys = [x.text.strip() for x in header_cols]

        if (not keys):
            return []

        rows = av_table.find_all('tr', recursive=False)

        if (not rows):
            return []

        rows = rows[1:]

        for row in rows:
            cols = row.find_all('td', recursive=False)
            values = [x.text.strip() for x in cols]
            if (keys):
                values = values[:len(keys)]
                av_results.append({keys[x]: values[x] for x in xrange(len(keys))})

        return av_results

    def _get_av_detections(self, result_url, data, action_result):

        headers = {
            'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) " +
                          "Gecko/20100101 Firefox/41.0"
        }

        if (not result_url.endswith('/')):
            result_url += '/'

        url = "{0}#static_avtivirus_tab".format(result_url)

        # get the report
        try:
            resp = requests.get(url, headers=headers)
        except Exception as e:
           return action_result.set_status(phantom.APP_ERROR, 'Unable to get the report', e)

        try:
            av_results = self._parse_av_table_response(resp, action_result)
        except Exception as e:
            self.debug_print("Handled exception", e)
            av_results = {}

        data[MALWR_JSON_AV_DETECTIONS] = av_results

        total_av_detections = [x for x in av_results if x['Signature'] != 'Clean']

        action_result.update_summary({MALWR_JSON_TOTAL_POSITIVES: len(total_av_detections)})

        return phantom.APP_SUCCESS

    def _handle_query_file(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login_to_malwr(action_result)

        if (phantom.is_fail(ret_val)):
            return self.get_status()

        # get the file from the vault
        vault_id = param[MALWR_JSON_VAULT_ID]

        try:
            resp = self._malwr_conn.submit_sample(Vault.get_file_path(vault_id),
                    share=param.get(MALWR_JSON_SHARE, True),
                    private=param.get(MALWR_JSON_PRIVATE, True),
                    analyze=param.get(MALWR_JSON_FORCE, True))
        except ValueError as e:
            return action_result.set_status(phantom.APP_ERROR, '', e)
        except Exception as e:
           return action_result.set_status(phantom.APP_ERROR, 'File submission failed', e)

        if (not resp):
            return action_result.set_status(phantom.APP_ERROR, 'File submission failed. No reply from server')

        action_result.add_debug_data(resp)

        analysis_link = resp.get('analysis_link')

        # if analysis is not complete the format of the analysis_link is:
        # /submission/status/MzE4N2FlNzZlYzBiNDQ2YWFkNWI3ZmIyOTk1NjNjZGI/
        # if complete the link is:
        # /analysis/Yzc4YWJlMTA4MWM1NGVmM2E1YmNkOGM4YmIyYzA1YzM/

        if (not analysis_link):
            return action_result.set_status(phantom.APP_ERROR, 'Did not get a link to the submission details')

        try:
            task_id = analysis_link.split('/')[-2]
        except Exception as e:
            self.debug_print("Handled exception", e)

        data = {}
        data[MALWR_JSON_TASK_ID] = task_id

        if ('status' not in analysis_link):

            action_result.add_data(data)
            result_url = "{0}{1}".format(MALWR_BASE_URL, analysis_link)
            data[MALWR_JSON_RESULT_URL] = result_url
            data[MALWR_JSON_STATUS] = "processed"
            self._get_av_detections(result_url, data, action_result)
            # done with the detonation
            return action_result.set_status(phantom.APP_SUCCESS, MALWR_DET_REPORT.format(result_url))

        ret_val, status = self._poll_task_status(task_id, action_result, analysis_link)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (status):
            action_result.add_data(data)
            result_url = "{0}{1}".format(MALWR_BASE_URL, MALWR_ANALYSIS_URI.format(task_id))
            data[MALWR_JSON_RESULT_URL] = result_url
            data[MALWR_JSON_STATUS] = "processed"
            self._get_av_detections(result_url, data, action_result)
            return action_result.set_status(phantom.APP_SUCCESS, MALWR_DET_REPORT.format(result_url))

        result_url = "{0}{1}".format(MALWR_BASE_URL, MALWR_ANALYSIS_URI.format(task_id))
        data[MALWR_JSON_RESULT_URL] = result_url
        data[MALWR_JSON_STATUS] = "pending"
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS, "Detonation process still ongoing. Please re-try after sometime")

    def handle_action(self, param):

        action = self.get_action_identifier()

        if (action == self.ACTION_ID_QUERY_FILE):
            result = self._handle_query_file(param)
        elif (action == self.ACTION_ID_GET_STATUS):
          result = self._get_status(param)
        elif (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
          result = self._test_connectivity(param)

        return result

if __name__ == '__main__':

    import sys
    import json
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MalwrConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
