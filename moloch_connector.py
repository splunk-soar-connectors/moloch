# File: moloch_connector.py
#
# Copyright (c) 2019-2021 Splunk Inc.
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
#
#
import ipaddress
import json
import os

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from requests.auth import HTTPDigestAuth

from moloch_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class MolochConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MolochConnector, self).__init__()

        self._state = None
        self._server_url = None
        self._port = None
        self._username = None
        self._password = None
        self._verify_server_cert = False

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name
        self._server_url = config[MOLOCH_CONFIG_SERVER_URL].strip('/')
        self._port = config.get(MOLOCH_CONFIG_PORT, 8005)
        self._username = config[MOLOCH_CONFIG_USERNAME]
        self._password = config[MOLOCH_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(MOLOCH_VERIFY_SERVER_CERT, False)

        # Custom validation for IP address
        self.set_validator(MOLOCH_PARAM_IP, self._is_ip)

        return phantom.APP_SUCCESS

    def _is_ip(self, ip_address):
        """ Function that checks given address and return True if address is valid IP address.

        :param ip_address: IP address
        :return: status (success/failure)
        """

        # Throws exception if IP is not valid IPv4 or IPv6
        try:
            ipaddress.ip_address(UnicodeDammit(ip_address).unicode_markup)
        except Exception as e:
            self.debug_print(MOLOCH_INVALID_IP, e)
            return False

        return True

    def _process_empty_reponse(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_pcap_response(self, response, action_result):
        """ This function is used to process pcap response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data') and (self.get_action_identifier() != "get_pcap" or not
                                                        (200 <= response.status_code < 399)):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'pcap' in response.headers.get('Content-Type', ''):
            return self._process_pcap_response(response, action_result)

        # Process an HTML resonse, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_reponse(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get",
                        timeout=None):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
            action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE (Default will be GET)
        :param timeout: Timeout for API call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        try:
            url = '{url}{endpoint}'.format(url=self._server_url, endpoint=endpoint)
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid URL. Please provide a valid URL"), resp_json)

        try:
            # In case of get_pcap action stream the response and store it into temp file
            if self.get_action_identifier() == 'get_pcap':
                r = request_func(url, auth=HTTPDigestAuth(self._username, self._password), json=data, headers=headers,
                                 verify=self._verify_server_cert, timeout=timeout, params=params, stream=True)
                # Create temp_file_path using asset_id
                temp_file_path = '{dir}{asset}_temp_pcap_file'.format(dir=self.get_state_dir(),
                                                                      asset=self.get_asset_id())

                # If API call is success
                if 200 <= r.status_code < 399:
                    # Store response into file
                    with open(temp_file_path, 'wb') as pcap_file:
                        for chunk in r.iter_content(chunk_size=1024):
                            if chunk:
                                pcap_file.write(chunk)

            else:
                r = request_func(url, auth=HTTPDigestAuth(self._username, self._password), json=data, headers=headers,
                                 verify=self._verify_server_cert, timeout=timeout, params=params)

        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used to test the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(MOLOCH_TEST_CONNECTION)

        # Validate port
        if not str(self._port).isdigit() or int(self._port) not in list(range(0, 65536)):
            self.save_progress(MOLOCH_TEST_CONNECTIVITY_FAILED)
            return action_result.set_status(phantom.APP_ERROR, status_message='{}. {}'.format(
                MOLOCH_CONNECTING_ERROR_MSG, MOLOCH_INVALID_CONFIG_PORT))

        params = {'length': 1}
        endpoint = ':{port}{endpoint}'.format(port=self._port, endpoint=MOLOCH_TEST_CONNECTIVITY_ENDPOINT)

        # make REST call
        ret_val, response = self._make_rest_call(endpoint=endpoint, params=params, action_result=action_result,
                                                 timeout=MOLOCH_TEST_CONNECTIVITY_TIMEOUT)

        if phantom.is_fail(ret_val):
            self.save_progress(MOLOCH_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()

        self.save_progress(MOLOCH_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_pcap(self, param):
        """ This function is used to get pcap file and store it into vault.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        # Validate port
        if not str(self._port).isdigit() or int(self._port) not in list(range(0, 65536)):
            self.debug_print(MOLOCH_INVALID_CONFIG_PORT)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_CONFIG_PORT)

        # Get parameters
        start_time = param[MOLOCH_JSON_START_TIME]
        end_time = param[MOLOCH_JSON_END_TIME]
        source_ip = param.get(MOLOCH_JSON_SOURCE_IP)
        dest_ip = param.get(MOLOCH_JSON_DESTINATION_IP)
        hostname = param.get(MOLOCH_JSON_HOSTNAME)
        custom_query = param.get(MOLOCH_JSON_CUSTOM_QUERY)
        limit = param.get(MOLOCH_JSON_LIMIT, 50)

        # Validate start_time parameter
        try:
            start_time = int(float(start_time))
        except:
            self.debug_print(MOLOCH_INVALID_START_TIME)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_START_TIME)

        # Validate end_time parameter
        try:
            end_time = int(float(end_time))
        except:
            self.debug_print(MOLOCH_INVALID_END_TIME)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_END_TIME)

        # Compare value of start_time and end_time
        if start_time >= end_time:
            self.debug_print(MOLOCH_INVALID_TIME_RANGE)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_TIME_RANGE)

        # Validate parameter limit
        try:
            limit = int(float(limit))
        except:
            self.debug_print(MOLOCH_INVALID_LIMIT_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_LIMIT_MSG)

        # Validate parameter limit
        if limit not in list(range(0, 2000001)):
            self.debug_print(MOLOCH_INVALID_LIMIT_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_LIMIT_MSG)

        params = dict()
        params['length'] = limit
        params['startTime'] = start_time
        params['stopTime'] = end_time

        expression = ''

        # Add source_ip to expression, if available
        if source_ip:
            expression = 'ip.src == {source_ip}'.format(source_ip=source_ip)

        # Add dest_ip to expression, if available
        if dest_ip:
            if expression:
                expression = '{expr} && ip.dst == {dst_ip}'.format(expr=expression, dst_ip=dest_ip)
            else:
                expression = 'ip.dst == {dst_ip}'.format(dst_ip=dest_ip)

        # Add hostname to expression, if available
        if hostname:
            if expression:
                expression = '{expr} && host.http == {hostname}'.format(expr=expression, hostname=hostname)
            else:
                expression = 'host.http == {hostname}'.format(hostname=hostname)

        # Add custom_query to expression, if available
        if custom_query:
            if expression:
                expression = '{expr} && {query}'.format(expr=expression, query=custom_query)
            else:
                expression = custom_query

        if expression:
            params['expression'] = expression

        endpoint = ':{port}{endpoint}'.format(port=self._port, endpoint=MOLOCH_GET_PCAP_ENDPOINT)

        # make REST call
        ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Create filename using input parameters
        filename = 'moloch_{start_time}_{end_time}'.format(start_time=start_time, end_time=end_time)

        if source_ip:
            filename = '{filename}_src_ip_{source_ip}'.format(filename=filename, source_ip=source_ip)

        if dest_ip:
            filename = '{filename}_dst_ip_{dst_ip}'.format(filename=filename, dst_ip=dest_ip)

        if hostname:
            filename = '{filename}_hostname_{hostname}'.format(filename=filename, hostname=hostname)

        filename = '{filename}_limit_{limit}'.format(filename=filename, limit=limit)

        filename = '{filename}.pcap'.format(filename=filename)

        temp_file_path = '{dir}{asset}_temp_pcap_file'.format(dir=self.get_state_dir(), asset=self.get_asset_id())

        # If file size is zero
        if not os.path.getsize(temp_file_path):
            # Delete file
            os.unlink(temp_file_path)
            self.debug_print(MOLOCH_NO_DATA_FOUND_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_NO_DATA_FOUND_MSG)

        # Check if file is text file
        # mime=True only returns mimetypes instead of textual description
        magic_obj = magic.Magic(mime=True)
        file_type = magic_obj.from_file(temp_file_path)

        if file_type == 'text/plain':
            with open(temp_file_path) as temp_file:
                temp_file_data = temp_file.read()

            message = 'Error while getting data from server. {api_message}'.\
                format(api_message=temp_file_data)

            self.debug_print(message)
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        invalid_chars = r'[]<>/\():;"\'|*()`~!@#$%^&+={}?,'

        # Remove special character defined in invalid_chars form filename
        try:
            filename = filename.translate(None, invalid_chars)
        except:
            # For Python v3 translate function expects a table for replacing the characters
            translate_table = {}
            for invalid_char in invalid_chars:
                translate_table[ord(invalid_char)] = None
            filename = filename.translate(translate_table)

        _, _, vault_file_list = ph_rules.vault_info(file_name=filename)
        vault_file_list = list(vault_file_list)

        # Iterate through files of Vault
        for file in vault_file_list:
            # If file name and file size are same file is duplicate
            if file.get('name') == filename and file.get('size') == os.path.getsize(temp_file_path):
                self.debug_print(MOLOCH_FILE_ALREADY_AVAILABLE)

                vault_file_details = {
                    phantom.APP_JSON_SIZE: file.get('size'),
                    phantom.APP_JSON_VAULT_ID: file.get('vault_id'),
                    'file_name': filename
                }
                summary['vault_id'] = file.get('vault_id')
                # Delete temp file
                os.unlink(temp_file_path)
                action_result.add_data(vault_file_details)
                return action_result.set_status(phantom.APP_SUCCESS)

        vault_file_details = {phantom.APP_JSON_SIZE: os.path.getsize(temp_file_path)}

        # Adding file to vault
        success, _, vault_id = ph_rules.vault_add(file_location=temp_file_path, container=self.get_container_id(), file_name=filename,
                                              metadata=vault_file_details)

        # Updating report data with vault details
        if not success:
            self.debug_print('Error while adding the file to vault')
            return action_result.set_status(phantom.APP_ERROR, status_message='Error while adding the file to vault')

        vault_file_details[phantom.APP_JSON_VAULT_ID] = vault_id
        vault_file_details['file_name'] = filename
        action_result.add_data(vault_file_details)

        summary['vault_id'] = vault_file_details['vault_id']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_fields(self, param):
        """ This function is used to list all fields.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        port = param.get(MOLOCH_PARAM_PORT, 9200)

        # Validate port
        if not str(port).isdigit() or int(port) not in list(range(0, 65536)):
            self.debug_print(MOLOCH_INVALID_PARAM_PORT)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_PARAM_PORT)

        endpoint = ':{port}{endpoint}'.format(port=port, endpoint=MOLOCH_LIST_FIELDS_ENDPOINT)

        # make REST call
        ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

        # Something went wrong
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "Status Code: 200" in message and "angular.module" in message:
                action_result.set_status(phantom.APP_ERROR, "Unable to connect to server. "
                                                            "Please make sure that entered port is correct")
            return action_result.get_status()

        # Add data to action_result
        for content in response.get("hits", {}).get("hits", []):
            action_result.add_data(content)

        summary = action_result.update_summary({})
        summary['total_fields'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_files(self, param):
        """ This function is used to list all files.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Validate port
        if not str(self._port).isdigit() or int(self._port) not in list(range(0, 65536)):
            self.debug_print(MOLOCH_INVALID_CONFIG_PORT)
            return action_result.set_status(phantom.APP_ERROR, status_message=MOLOCH_INVALID_CONFIG_PORT)

        endpoint = ':{port}{endpoint}'.format(port=self._port, endpoint=MOLOCH_LIST_FILES_ENDPOINT)

        # make REST call
        ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

        # Something went wrong
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add data to action_result
        for content in response["data"]:
            action_result.add_data(content)

        summary = action_result.update_summary({})
        summary['total_files'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'get_pcap': self._handle_get_pcap,
            'list_files': self._handle_list_files,
            'list_fields': self._handle_list_fields
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MolochConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
