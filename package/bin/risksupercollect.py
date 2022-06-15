#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__email___ = "gmarchand@splunk.com"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import logging
import splunk
import splunk.entity
import time
import json
import re
from collections import OrderedDict
import ast
import csv
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/risk_supercollect.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-risk-superhandler', 'lib'))

# import Splunk libs
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six
import splunklib.client as client
import splunklib.results as results

@Configuration()
class RiskSuperCollect(StreamingCommand):

    # The risk index target
    index = Option(
        doc='''
        **Syntax:** **Override the risk index target****
        **Description:** Risk index.''',
        require=False, validate=validators.Match("index", r"^.*$"))

    # the search_name value, will be applied against the source
    search_name = Option(
        doc='''
        **Syntax:** **The search name value****
        **Description:** search_name.''',
        require=False, validate=validators.Match("search_name", r"^.*$"))

    # The risk rules JSON object
    risk_rules = Option(
        doc='''
        **Syntax:** **The risk rules JSON obkect****
        **Description:** risk_rules.''',
        require=False, validate=validators.Match("risk_rules", r"^.*$"))


    def stream(self, records):

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_risk_superhandler_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                        namespace='TA-risk-superhandler', sessionKey=session_key, owner='-')
        mydict = entity
        splunkd_port = mydict['mgmtHostPort']
        splunkd_host = entity['host']

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-risk-superhandler",
            port=splunkd_port,
            token=session_key
        )

        # Get conf
        default_risk_index = None
        for stanza in confs:
            if stanza.name == "index_settings":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "risk_index":
                        default_risk_index = stanzavalue

        # Define Meta
        splunk_index = self.index
        splunk_sourcetype = "risk:json"
        splunk_source = self.search_name
        splunk_host = splunkd_host

        # If the index is specified in arguments, this will override the final target
        if self.index:
            splunk_index = self.index
        else:
            splunk_index = default_risk_index
        logging.debug("risk_index=\"{}\"".format(splunk_index))

        # The source definition should match "- Rule" or "AdHoc Risk Score" to get the mitre attack enrichment automatically
        # If the submitted value does not comply with this, it will be overriden
        if not re.search("\-\sRule", splunk_source):
            logging.warn("The provided search_name=\"{}\" value does not comply with risk requirement, overriding to \"AdHoc Risk Score\" to allow auto-lookup")
            splunk_source = "AdHoc Risk Score"

        # Load the risk rules JSON object
        try:
            risk_json_rules = json.loads(self.risk_rules)
            logging.debug("risk_rules=\"{}\" were successfully loaded as a JSON object".format(self.risk_rules))
        except Exception as e:
            logging.error("Failure to load risk_rules as a proper JSON object, risk_rules=\"{}\", exception=\"{}\"".format(self.risk_rules, e))

        # Loop in the results
        for record in records:

            # get time, if any
            time_event = None
            try:
                time_event = record['_time']
            except Exception as e:
                time_event = time.time()

            # create a summary record
            summary_record = {}

            # Add _time first
            summary_record['_time'] = str(time_event)

            # loop through the dict
            for k in record:
                logging.debug("field=\"{}\", value=\"{}\"".format(k, record[k]))

                # Exclude the event time, add existing fields
                if k != '_time':
                    summary_record[k] = record[k]

                # Handle threats

                threat_object_field_list = []
                threat_object_type_list = []
                
                # This is not OOTB, but provides a better value
                threat_objects = {}

                for jsonSubObj in risk_json_rules:
                    json_threat_object = None

                    try:
                        logging.debug("Attempting to extract threat pair keys from jsonSubObj=\"{}\"".format(jsonSubObj))
                        threat_object_field = jsonSubObj['threat_object_field']
                        threat_object_type = jsonSubObj['threat_object_type']
                        json_threat_object = True
                    except Exception as e:
                        logging.debug("No threat object in jsonSubObj=\"{}\"".format(jsonSubObj))
                        json_threat_object = None

                    # Add
                    if json_threat_object:

                        try:
                            logging.debug("Adding threat pair keys")
                            threat_object_field_list.append(record[threat_object_field])
                            threat_object_type_list.append(threat_object_type)
                            threat_objects[threat_object_type] = record[threat_object_field]

                        except Exception as e:
                            logging.error("Failed to insert threat pair keys, exception=\"{}\"".format(e))

                    # Add to the final object
                    if len(threat_object_field_list)>0:
                        summary_record['threat_object'] = threat_object_field_list
                    if len(threat_object_type_list)>0:
                        summary_record['threat_object_type'] = threat_object_type_list
                    if threat_objects:
                        summary_record['threat_objects'] = threat_objects

            # index the audit record
            try:
                target = service.indexes[splunk_index]
                target.submit(event=json.dumps(summary_record), source=str(splunk_source) ,sourcetype=str(splunk_sourcetype), host=str(splunk_host))
                logging.info("Risk event created successfully")
                logging.debug("record=\"{}\"".format(json.dumps(summary_record, indent=1)))
            except Exception as e:
                logging.error("Risk event creation failure, record=\"{}\", exception=\"{}\"".format(json.dumps(summary_record, indent=1), e))

            # yield
            yield summary_record

dispatch(RiskSuperCollect, sys.argv, sys.stdin, sys.stdout, __name__)
