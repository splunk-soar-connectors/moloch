# File: moloch_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

MOLOCH_CONFIG_SERVER_URL = 'server_url'
MOLOCH_CONFIG_PORT = 'port'
MOLOCH_CONFIG_USERNAME = 'username'
MOLOCH_CONFIG_PASSWORD = 'password'
MOLOCH_VERIFY_SERVER_CERT = 'verify_server_cert'
MOLOCH_TEST_CONNECTION = 'Querying endpoint to verify the credentials provided'
MOLOCH_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
MOLOCH_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
MOLOCH_INVALID_TIME_RANGE = "Invalid time range. 'end_time' should be greater than 'start_time'."
MOLOCH_FILE_ALREADY_AVAILABLE = 'File already available in Vault'
MOLOCH_INVALID_IP = "Parameter 'ip' failed validation"
MOLOCH_INVALID_LIMIT_MSG = "Parameter 'limit' failed validation"
MOLOCH_INVALID_START_TIME = "Parameter 'start_time' failed validation"
MOLOCH_INVALID_END_TIME = "Parameter 'end_time' failed validation"
MOLOCH_INVALID_CONFIG_PORT = "Invalid value for config parameter 'port'"
MOLOCH_INVALID_PARAM_PORT = "Parameter 'port' failed validation"
MOLOCH_NO_DATA_FOUND_MSG = 'No packets found'
MOLOCH_CONNECTING_ERROR_MSG = 'Error connecting to server'
MOLOCH_TEST_CONNECTIVITY_ENDPOINT = '/sessions.json'
MOLOCH_GET_PCAP_ENDPOINT = '/sessions.pcap'
MOLOCH_TEST_CONNECTIVITY_TIMEOUT = 30
MOLOCH_LIST_FILES_ENDPOINT = "/file/list"
MOLOCH_PARAM_PORT = "port"
MOLOCH_LIST_FIELDS_ENDPOINT = "/fields/_search?size=1000"
MOLOCH_PARAM_IP = 'ip'
MOLOCH_JSON_SOURCE_IP = 'source_ip'
MOLOCH_JSON_DESTINATION_IP = 'destination_ip'
MOLOCH_JSON_START_TIME = 'start_time'
MOLOCH_JSON_END_TIME = 'end_time'
MOLOCH_JSON_HOSTNAME = 'hostname'
MOLOCH_JSON_CUSTOM_QUERY = 'custom_query'
MOLOCH_JSON_LIMIT = 'limit'
