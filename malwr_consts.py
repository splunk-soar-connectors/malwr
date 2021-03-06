# File: malwr_consts.py
#
# Copyright (c) 2016-2017 Splunk Inc.
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
MALWR_JSON_API_KEY = "api_key"
MALWR_JSON_BASE_URL = "base_url"
MALWR_JSON_PRIVATE = "private"
MALWR_JSON_VAULT_ID = "vault_id"
MALWR_JSON_FILE_NAME = "filename"
MALWR_JSON_FORCE = "force"
MALWR_JSON_USERNAME = "username"
MALWR_JSON_PASSWORD = "password"
MALWR_JSON_TASK_ID = "id"
MALWR_JSON_RESULT_URL = "result_url"
MALWR_JSON_STATUS = "status"
MALWR_JSON_SHARE = "share"
MALWR_JSON_PRIVATE = "private"
MALWR_JSON_FORCE = "force"
MALWR_JSON_AV_DETECTIONS = "av_detections"
MALWR_JSON_TOTAL_POSITIVES = "total_positives"

MALWR_ERR_SERVER_CONNECTION = "Error connecting to server"
MALWR_ERR_FROM_SERVER = "Error from server. Status: {status}, Details: {detail}"
MALWR_ERR_JSON_PARSE = "Response from server does not look like a valid Json. Data from server: {data}"
MALWR_ERR_DATA_FROM_SERVER = "Response from server does not contain required data. Message from server: {message}"

MALWR_SLEEP_SECS = 10
MALWR_BASE_URL = "https://malwr.com"
MALWR_ANALYSIS_URI = '/analysis/{0}/'
MALWR_DET_REPORT = 'File processed. Detonation results can be found <a href="{0}"><b><u>here</u></b>.</a>'
