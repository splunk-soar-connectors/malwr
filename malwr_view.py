# File: malwr_view.py
#
# Copyright (c) 2014-2017 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
from malwr_consts import *
from phantom.json_keys import *


def detonate_file(provides, all_results, context):

    context['rows'] = rows = []
    context['headers'] = ['vault_id', 'status', 'positives', 'task id', 'report']
    context['title1'] = "File"
    context['title2'] = 'Detonation'

    context['allow_links'] = [context['headers'].index('report')]

    for summary, action_results in all_results:
        for result in action_results:
            parameter = result.get_param()
            data = result.get_data()
            if (not data):
                continue

            summary = result.get_summary()

            for item in data:
                new_row = []
                rows.append(new_row)

                new_row.append({'value': parameter.get(MALWR_JSON_VAULT_ID), 'contains': ['pe file']})
                new_row.append({'value': item.get(MALWR_JSON_STATUS)})

                if (summary):
                    new_row.append({'value': summary.get(MALWR_JSON_TOTAL_POSITIVES)})
                else:
                    new_row.append({'value': 0})

                new_row.append({'value': item.get(MALWR_JSON_TASK_ID), 'contains': ['malwr task id']})
                new_row.append({'value': item.get(MALWR_JSON_RESULT_URL)})

    return '/widgets/generic_table.html'


def get_results(provides, all_results, context):

    context['rows'] = rows = []
    context['headers'] = ['task id', 'status', 'positives', 'report']
    context['title1'] = "Detonation"
    context['title2'] = 'Results'

    context['allow_links'] = [context['headers'].index('report')]

    for summary, action_results in all_results:
        for result in action_results:
            # parameter = result.get_param()
            data = result.get_data()
            if (not data):
                continue

            summary = result.get_summary()

            for item in data:
                new_row = []
                rows.append(new_row)

                new_row.append({'value': item.get(MALWR_JSON_TASK_ID), 'contains': ['malwr task id']})

                new_row.append({'value': item.get(MALWR_JSON_STATUS)})

                if (summary):
                    new_row.append({'value': summary.get(MALWR_JSON_TOTAL_POSITIVES)})
                else:
                    new_row.append({'value': 0})

                new_row.append({'value': item.get(MALWR_JSON_RESULT_URL)})

    return '/widgets/generic_table.html'
