Release notes
-------------

Version 1.0.28
==============

- Refresh Splunk UCC, Splunk Python SDK and others libs to address Appinspect vetting removal due to outdated dependencies

Version 1.0.27
==============

- enhancement - Dedup - Automatically take into account cim_entity_zone if available in the upstream results #18
- change - Upgrade to Splunk Python SDK 2.0.1 #17
- logging for dedup - Ensures consistent logging for dedup operations for both the custom command and alert action #20

Version 1.0.26
==============

- feature - Provide dedup capabilities handled at the level of the backend #14
- bug - Exclusions for risk_object and threat_pbject are no behaving properly and should be case insensitive #16

Version 1.0.25
==============

- Fix: logs are incorrectly claiming that none of the risk objects could be extracted at least one risk object cannot be extracted, instead of no risk match for any of the risk objects in the JSON definition

Version 1.0.24
==============

- Enhancement: If a risk_score value is set at the search level before the action is called, this should override the definition as per the Risk out of the box behaviour in ES

Version 1.0.23
==============

- Enhancement: blocklist advanced patterns features for risk_objects and threat objects
- Fix: Incorrect logging message via the modalert in some circumstances regarding the presence or not at valid risk object

Version 1.0.22
==============

- Enhancement: logging improvement, if we fail to retrieve the uc_ref from the upstream result, log the event itself to ease its identification
- Enhancement: similarly, if this first requirement is not met, do not continue the execution for that record to avoid a general exception

Version 1.0.21
==============

- Enhancement: Detect if a risk_object is incorrectly set with a field format separator while it is coming as a native list of items
- Enhancement: Improve logging when none of the defined risk_object can be extracted from the upstream results

Version 1.0.20
==============

- Enhancement: Avoid running the risk action if all risk objects failed to be extracted due to an incorrect risk definition or unexpected events results

Version 1.0.19
==============

- Enhancement: Allows the threat_object to be specified as part of a custom multivalue field seprated by a specific delimitor
- Enhancement: Avoid running the risk action if all risk objects failed to be extracted due to an incorrect risk definition or unexpected events results

Version 1.0.18
==============

- Fix: Missing uc_ref mention in exception logs

Version 1.0.17
==============

- Enhancement: Handle an incorrect format separator definition provided for a field that is actually a multi-value field

Version 1.0.16
==============

- Enhancement: Avoid requiring the list_settings capabilty to run the modalert action or custom commands

Version 1.0.15
==============

- Enhancement: Addresses the deprecation of the Python SDK results.ResultsReader method replaced by results.JSONResultsReader
- Enhancement: Allows enforcing a service account if running the risksuperhandler custom command, this allows avoiding generating risks unless the user running the command matches the value set
- Enhancement: Avoid failing if the user lacks privileges to retrieve the app level logging level configuration
- Docs: fix some typos

Version 1.0.14
==============

- Enhancement: Avoid using spath at riskjsonload stage, transparently generate upstream fields without the need to rely on spath and risk its own limitations

Version 1.0.13
==============

- Fix: Avoid failing to generate a risk event if the first risk_object in the risk definition is missing from the events

Version 1.0.12
==============

- Initial public release