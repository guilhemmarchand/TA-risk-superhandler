Compatibility
-------------

Splunk compatibility
####################

This application is compatible with Splunk 8.0.x and later.

Python support
##############

Only Python 3 is supported.

Splunk Enterprise Security
##########################

The Risk super handler underneath relies on the built-in Splunk Enterprise Risk framework, and therefore is compatible with Enterprise Security from version 6.4.x.

Before Enterprise Security 6.5, threats objects were not supported by the collectrisk command, however the Add-on handles things in way that generate threat objects for any version of Enterprise Security.

Standalone deployment, distributed and Search Head Cluster
##########################################################

The Risk Super Handler is compatible with any kind of Splunk deployment.