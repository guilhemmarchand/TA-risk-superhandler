# Risk Super Handler for Splunk Enterprise Security - Implement Risk Based Alerting

# Binary File Declaration
lib/charset_normalizer/md__mypyc.cpython-38-x86_64-linux-gnu.so
lib/charset_normalizer/md.cpython-310-x86_64-linux-gnu.so

## The Risk Super handler for Splunk Enterprise security provides services for

- Generating risk events using the Splunk Enterprise Security risk framework for **Risk Based Alerting purposes (RBA)** with additional levels of features
- Centralizing the risk definition in a central lookup file referencial, rather than configured on a per correlation search basis
- Defining a use case reference logic, which is used to lookup the risk definition and allows advanced dynamic rule definition use cases
- Allowing different levels of risk objects definition, with different risk messages and risk score per risk object
- Facilitating the transition from a traditional SIEM detection per use case to a Risk Based Alerting approach (RBA)

_In a nutshell:_

- A lookup file is created and acts as the central reference for the Risk Rules (RR) use cases, and their risk definition
- The application provides a "Risk super" alert action which can be enabled per Risk Rule correletation search, as well as a streaming custom command that can be called directly to generate the risk events from upstream results
- When the Risk Rule triggers, the backend lookups the use case referencial for a match with the use case reference, if there is a match, it loads the risk rules definition from the lookup
- The Risk definition is applied to the results of the correlation search, and submits these in a pre-formated manner to the Splunk Enterprise Security collectrisk custom command
- Risk events are created transparently depending on the risk rules and the events content
- Risk messages can differ per risk object, as well as the risk score

See the online documentation: https://TA-risk-superhandler.readthedocs.io/en/latest/
