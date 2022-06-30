#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__email___ = "gmarchand@splunk.com"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import splunk
import splunk.entity
import requests
import json
import re
import time
import logging

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/riskjsonload.log", 'a')
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

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client


@Configuration(distributed=False)

class JsonRestHandler(GeneratingCommand):

    json_path = Option(
        doc='''
        **Syntax:** **The json file path****
        **Description:** JSON dict.''',
        require=False, validate=validators.Match("json_path", r"^.*$"))

    def generate(self, **kwargs):

        # set loglevel
        try:
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
        except Exception as e:
            logging.warning("failed to retriieve application level logging with exception=\"{}\"".format(e))

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        try:
            splunkd_port_search = re.search(':(\d+)$', self._metadata.searchinfo.splunkd_uri, re.IGNORECASE)
            if splunkd_port_search:
                splunkd_port = splunkd_port_search.group(1)
                logging.debug("splunkd_port=\"{}\" extracted successfully from splunkd_uri=\"{}\"".format(splunkd_port, self._metadata.searchinfo.splunkd_uri))
        except Exception as e:
            logging.error("Failed to extract splunkd_port from splunkd_uri with exception=\"{}\"".format(e))
            splunkd_port = "8089"

        # temp
        f = open(self.json_path)

        records = json.load(f)

        logging.debug("records=\"{}\"".format(records))

        for record in records:

            # We do not touch the raw events, let's render again
            # get time, if any
            has_time = None
            try:
                has_time = record['_time']
            except Exception as e:
                has_time = None

            # get all other fields

            # create a final record
            yield_record = {}

            # loop through the dict
            for k in record:
                # This debug is very noisy
                # logging.debug("field=\"{}\"".format(k))

                # if not our input field, and not _time
                if k != '_time':
                    yield_record[k] = record[k]

            # if time was defined, add it
            if has_time:
                yield_record['_time'] = record['_time']

            # Add _raw
                yield_record['_raw'] = record

            # yield
            logging.debug("record=\"{}\"".format(yield_record))
            yield yield_record            


dispatch(JsonRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
