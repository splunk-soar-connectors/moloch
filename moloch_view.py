# File: moloch_view.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

from datetime import datetime


def get_ctx_result(provides, result):
    """ Function that parses data.

    :param result: result
    :param provides: action name
    :return: response data
    """

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    if provides == 'get pcap':
        # If error occurs while converting epoch to iso time format
        try:
            param['start_time'] = '{}Z'.format(datetime.utcfromtimestamp(int(param['start_time'])).isoformat())
            param['end_time'] = '{}Z'.format(datetime.utcfromtimestamp(int(param['end_time'])).isoformat())
        except:
            ctx_result['data'] = {}
            return ctx_result

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary
    ctx_result['action'] = provides
    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = _parse_data(data, provides)

    return ctx_result


def _parse_data(data, provides):
    """ Function that parse data.

    :param provides: action name
    :param data: response data
    :return: response data
    """

    if provides == "list files":
        for item in data:
            if item.get('first'):
                item['first'] = "{}Z".format(datetime.utcfromtimestamp(item['first']).isoformat())

            if item.get('locked') == 0:
                item['locked'] = False
            else:
                item['locked'] = True

    if provides == "list fields":
        for index, item in enumerate(data):
            if item.get('_id'):
                data[index]['id'] = item['_id']
            if item.get('_source'):
                data[index]['source'] = item['_source']

    return data


def display_view(provides, all_app_runs, context):
    """ Function that displays view.

    :param provides: action name
    :param context: context
    :param all_app_runs: all app runs
    :return: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "list files":
        return_page = "moloch_list_files.html"
    elif provides == "list fields":
        return_page = "moloch_list_fields.html"
    elif provides == "get pcap":
        return_page = "moloch_get_pcap.html"

    return return_page
