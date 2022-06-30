Release notes
-------------

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