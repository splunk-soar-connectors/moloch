# Moloch

Publisher: Splunk Community \
Connector Version: 3.0.0 \
Product Vendor: Moloch \
Product Name: Moloch \
Minimum Product Version: 5.1.0

This app integrates with Moloch to support various investigative actions

### Configuration variables

This table lists the configuration variables required to operate Moloch. These variables are specified when configuring a Moloch asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server_url** | required | string | Server URL (e.g. http://10.10.10.10) |
**port** | optional | numeric | Moloch port |
**username** | required | string | Username |
**password** | required | password | Password |
**verify_server_cert** | optional | boolean | Verify Server Certificate |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[get pcap](#action-get-pcap) - Download the pcap file from server and add it to the vault \
[list fields](#action-list-fields) - List all fields on which user can query \
[list files](#action-list-files) - List all pcap files

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get pcap'

Download the pcap file from server and add it to the vault

Type: **investigate** \
Read only: **True**

Parameter <b>limit</b> has a range of 0 to 2000000.<br>Parameter <b>custom_query</b> is case sensitive. Example for custom query of get_pcap action<br>port.src == 80 || port.dst == 80 && country != USA.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | required | Start time in epoch | numeric | |
**end_time** | required | End time in epoch | numeric | |
**source_ip** | optional | Source IP | string | `ip` |
**destination_ip** | optional | Destination IP | string | `ip` |
**hostname** | optional | Hostname | string | `host name` |
**custom_query** | optional | Custom query | string | `moloch field` |
**limit** | optional | Maximum number of sessions to return (Default: 50) | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.custom_query | string | `moloch field` | port.src==67 |
action_result.parameter.destination_ip | string | `ip` | 10.0.2.4 |
action_result.parameter.end_time | numeric | | 1519019114 |
action_result.parameter.hostname | string | `host name` | 10.0.3.115:8005 |
action_result.parameter.limit | numeric | | 10 |
action_result.parameter.source_ip | string | `ip` | 10.2.3.4 |
action_result.parameter.start_time | numeric | | 1519018114 |
action_result.data.\*.file_name | string | `file name` | moloch_1519018114_1519021714_limit_100.pcap |
action_result.data.\*.size | numeric | `file size` | 13628877 |
action_result.data.\*.vault_id | string | `vault id` | dc92fe345c7c8c846053fe379797353db92a540a |
action_result.summary.vault_id | string | `vault id` | dc92fe345c7c8c846053fe379797353db92a540a |
action_result.message | string | | Vault id: dc92fe345c7c8c846053fe379797353db92a540a |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list fields'

List all fields on which user can query

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**port** | optional | Elasticsearch port (Default: 9200) | numeric | `port` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.port | numeric | `port` | 9200 |
action_result.data.\*.\_id | string | | ip |
action_result.data.\*.\_index | string | | fields_v1 |
action_result.data.\*.\_score | numeric | | 1 |
action_result.data.\*.\_source.aliases | string | | socks.port |
action_result.data.\*.\_source.category | string | | host |
action_result.data.\*.\_source.dbField | string | | ipall |
action_result.data.\*.\_source.friendlyName | string | | All IP fields |
action_result.data.\*.\_source.group | string | | general |
action_result.data.\*.\_source.help | string | | Search all ip fields |
action_result.data.\*.\_source.noFacet | string | | true |
action_result.data.\*.\_source.portField | string | | portall |
action_result.data.\*.\_source.rawField | string | | rawas1 |
action_result.data.\*.\_source.regex | string | | (^port\\.(?:(?!\\.cnt$).)\*$|\\.port$) |
action_result.data.\*.\_source.requiredRight | string | | emailSearch |
action_result.data.\*.\_source.transform | string | | ipProtocolLookup |
action_result.data.\*.\_source.type | string | | ip |
action_result.data.\*.\_type | string | | field |
action_result.summary.total_fields | numeric | | 250 |
action_result.message | string | | Total fields: 250 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list files'

List all pcap files

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.data.\*.first | numeric | | 1518098524 |
action_result.data.\*.id | string | | test-1 |
action_result.data.\*.locked | numeric | | 0 |
action_result.data.\*.name | string | `file path` | /data/moloch/raw/test-180208-00000001.pcap |
action_result.data.\*.node | string | | test |
action_result.data.\*.num | numeric | | 1 |
action_result.summary.total_files | numeric | | 2 |
action_result.message | string | | Total files: 2 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
