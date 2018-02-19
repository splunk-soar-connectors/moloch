# --
# File: moloch_view.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

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

    return return_page
