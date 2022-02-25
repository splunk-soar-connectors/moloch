[comment]: # "Auto-generated SOAR connector documentation"
# Moloch

Publisher: Splunk Community  
Connector Version: 3\.0\.0  
Product Vendor: Moloch  
Product Name: Moloch  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with Moloch to support various investigative actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Moloch asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | Server URL \(e\.g\. http\://10\.10\.10\.10\)
**port** |  optional  | numeric | Moloch port
**username** |  required  | string | Username
**password** |  required  | password | Password
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get pcap](#action-get-pcap) - Download the pcap file from server and add it to the vault  
[list fields](#action-list-fields) - List all fields on which user can query  
[list files](#action-list-files) - List all pcap files  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get pcap'
Download the pcap file from server and add it to the vault

Type: **investigate**  
Read only: **True**

Parameter <b>limit</b> has a range of 0 to 2000000\.<br>Parameter <b>custom\_query</b> is case sensitive\. Example for custom query of get\_pcap action<br>port\.src == 80 \|\| port\.dst == 80 && country \!= USA\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  required  | Start time in epoch | numeric | 
**end\_time** |  required  | End time in epoch | numeric | 
**source\_ip** |  optional  | Source IP | string |  `ip` 
**destination\_ip** |  optional  | Destination IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 
**custom\_query** |  optional  | Custom query | string |  `moloch field` 
**limit** |  optional  | Maximum number of sessions to return \(Default\: 50\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.custom\_query | string |  `moloch field` 
action\_result\.parameter\.destination\_ip | string |  `ip` 
action\_result\.parameter\.end\_time | numeric | 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.source\_ip | string |  `ip` 
action\_result\.parameter\.start\_time | numeric | 
action\_result\.data\.\*\.file\_name | string |  `file name` 
action\_result\.data\.\*\.size | numeric |  `file size` 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list fields'
List all fields on which user can query

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**port** |  optional  | Elasticsearch port \(Default\: 9200\) | numeric |  `port` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.port | numeric |  `port` 
action\_result\.data\.\*\.\_id | string | 
action\_result\.data\.\*\.\_index | string | 
action\_result\.data\.\*\.\_score | numeric | 
action\_result\.data\.\*\.\_source\.aliases | string | 
action\_result\.data\.\*\.\_source\.category | string | 
action\_result\.data\.\*\.\_source\.dbField | string | 
action\_result\.data\.\*\.\_source\.friendlyName | string | 
action\_result\.data\.\*\.\_source\.group | string | 
action\_result\.data\.\*\.\_source\.help | string | 
action\_result\.data\.\*\.\_source\.noFacet | string | 
action\_result\.data\.\*\.\_source\.portField | string | 
action\_result\.data\.\*\.\_source\.rawField | string | 
action\_result\.data\.\*\.\_source\.regex | string | 
action\_result\.data\.\*\.\_source\.requiredRight | string | 
action\_result\.data\.\*\.\_source\.transform | string | 
action\_result\.data\.\*\.\_source\.type | string | 
action\_result\.data\.\*\.\_type | string | 
action\_result\.summary\.total\_fields | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list files'
List all pcap files

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.first | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.locked | numeric | 
action\_result\.data\.\*\.name | string |  `file path` 
action\_result\.data\.\*\.node | string | 
action\_result\.data\.\*\.num | numeric | 
action\_result\.summary\.total\_files | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 