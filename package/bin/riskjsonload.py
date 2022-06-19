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
        splunkd_port = entity['mgmtHostPort']

        # temp
        f = open(self.json_path)

        records = json.load(f)

        logging.debug("records=\"{}\"".format(records))

        for record in records:
            yield {'_time': time.time(), '_raw': record }

dispatch(JsonRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
