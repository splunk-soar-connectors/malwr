[comment]: # "Auto-generated SOAR connector documentation"
# Malwr

Publisher: Phantom  
Connector Version: 1\.0\.25  
Product Vendor: Malwr  
Product Name: Malwr  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.190  

This app implements <b>investigative</b> actions on the Malwr cloud based sandbox\.

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Malwr asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials\.  
[detonate file](#action-detonate-file) - Run the file in the sandbox and retrieve part of the analysis results\.  
[get report](#action-get-report) - Query for status of a submitted detonation task in Malwr\.  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Run the file in the sandbox and retrieve part of the analysis results\.

Type: **investigate**  
Read only: **True**

Some things to note\:<ul><li>This action requires the input file to be present in the vault and therefore takes the vault id as a parameter\.</li><li>The rendered widget contains a link to the results on the malwr site\.</li><li>Possible values for the detonation status \(set in <b>action\_result\.data\.\*\.status</b>\) are\:<ul><li>processed</li><li>pending</li></ul><li>After submitting the file, the action polls the service to check the status\. It polls for a finite number of times, before giving up and returning a <b>pending</b> result\. In case this happens, please re\-run the <b>get report</b> action at a later time\.</li><li>AV detections if any are part of the result data\. For the rest of the report, please visit the result link that is part of the rendered widget\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `hash`  `pe file`  `flash`  `pdf`  `doc` 
**private** |  optional  | Keep the analysis private | boolean | 
**share** |  optional  | Share the file with the community | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.vault\_id | string |  `hash`  `pe file`  `flash`  `pdf`  `doc` 
action\_result\.parameter\.share | boolean | 
action\_result\.parameter\.private | boolean | 
action\_result\.data\.\*\.id | string |  `malwr task id` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.av\_detections | string | 
action\_result\.summary\.total\_positives | numeric | 
action\_result\.data\.\*\.result\_url | string |  `url`  `domain` 
action\_result\.data\.\*\.message | string | 
action\_result\.status | string |   

## action: 'get report'
Query for status of a submitted detonation task in Malwr\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Task ID to get the results of | string |  `malwr task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.id | string |  `malwr task id` 
action\_result\.data\.\*\.id | string |  `malwr task id` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.result\_url | string |  `url`  `domain` 
action\_result\.data\.\*\.av\_detections | string | 
action\_result\.summary\.total\_positives | numeric | 
action\_result\.data\.\*\.message | string | 
action\_result\.status | string | 