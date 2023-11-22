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
import tempfile
from collections import OrderedDict
import ast
import csv
import re
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = logging.FileHandler(
    splunkhome + "/var/log/splunk/risk_superhandler.log", "a"
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-risk-superhandler", "lib"))

# import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)
from splunklib import six
import splunklib.client as client
import splunklib.results as results

# import cim_modactions
sys.path.append(os.path.join(splunkhome, "etc", "apps", "Splunk_SA_CIM", "lib"))
import cim_actions


@Configuration()
class RiskSuperHandler(StreamingCommand):
    uc_lookup_path = Option(
        doc="""
        **Syntax:** **The dictionnary lookup path****
        **Description:** use case reference lookup path.""",
        require=True,
        validate=validators.Match("uc_lookup_path", r"^.*$"),
    )

    uc_ref_field = Option(
        doc="""
        **Syntax:** **The name of the field containing the use case reference****
        **Description:** use case reference field name.""",
        require=True,
        validate=validators.Match("uc_ref_field", r"^.*$"),
    )

    uc_svc_account = Option(
        doc="""
        **Syntax:** **Check service account****
        **Description:** If this option is set, risk events will be generated only the user username running the command matches this value.""",
        require=False,
        validate=validators.Match("uc_svc_account", r"^.*$"),
    )

    # status will be statically defined as imported

    def stream(self, records):
        # set loglevel
        try:
            loglevel = "INFO"
            conf_file = "ta_risk_superhandler_settings"
            confs = self.service.confs[str(conf_file)]
            for stanza in confs:
                if stanza.name == "logging":
                    for stanzakey, stanzavalue in stanza.content.items():
                        if stanzakey == "loglevel":
                            loglevel = stanzavalue
            logginglevel = logging.getLevelName(loglevel)
            log.setLevel(logginglevel)
        except Exception as e:
            logging.warning(
                'failed to retriieve application level logging with exception="{}"'.format(
                    e
                )
            )

        #
        # Advanced configuration
        #

        # retrive the list of risk_object block list patterns (optional)
        try:
            blocklist_risk_object_patterns_tmp = []
            blocklist_risk_object_patterns = []

            for stanza in confs:
                if stanza.name == "advanced_configuration":
                    for key, value in stanza.content.items():
                        if key == "blocklist_risk_object_patterns" and value:
                            blocklist_risk_object_patterns_tmp = re.split(
                                r',(?=")', value
                            )

            # handle double quotes
            for blocklist_pattern in blocklist_risk_object_patterns_tmp:
                result = re.match(r"\"([^\"]*)\"", blocklist_pattern)
                if result:
                    blocklist_risk_object_patterns.append(result.group(1))
            logging.debug(
                'blocklist, a list for risk_object forbidden value was provided blocklist_risk_object_patterns="{}"'.format(
                    blocklist_risk_object_patterns
                )
            )
        except Exception as e:
            logging.error(
                'failed to retrieve risk_object blocklist with exception="{}"'.format(
                    str(e)
                )
            )
            blocklist_risk_object_patterns = []

        # retrive the list of threat_object block list patterns (optional)
        try:
            blocklist_threat_object_patterns_tmp = []
            blocklist_threat_object_patterns = []

            for stanza in confs:
                if stanza.name == "advanced_configuration":
                    for key, value in stanza.content.items():
                        if key == "blocklist_threat_object_patterns" and value:
                            blocklist_threat_object_patterns_tmp = re.split(
                                r',(?=")', value
                            )

            # handle double quotes
            for blocklist_pattern in blocklist_threat_object_patterns_tmp:
                result = re.match(r"\"([^\"]*)\"", blocklist_pattern)
                if result:
                    blocklist_threat_object_patterns.append(result.group(1))
            logging.debug(
                'blocklist, a list for threat_object forbidden value was provided blocklist_threat_object_patterns="{}"'.format(
                    blocklist_threat_object_patterns
                )
            )
        except Exception as e:
            logging.error(
                'failed to retrieve threat_object blocklist with exception="{}"'.format(
                    str(e)
                )
            )
            blocklist_threat_object_patterns = []

        # To trace all attr
        # logging.debug("Trace all meta")
        # logging.debug(vars(self))
        # logging.debug(vars(confs))
        # logging.debug(vars(stanza))
        # logging.debug(dir())
        # logging.debug("name is=\"{}\"".format(self.name))

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        try:
            splunkd_port_search = re.search(
                ":(\d+)$", self._metadata.searchinfo.splunkd_uri, re.IGNORECASE
            )
            if splunkd_port_search:
                splunkd_port = splunkd_port_search.group(1)
                logging.debug(
                    'splunkd_port="{}" extracted successfully from splunkd_uri="{}"'.format(
                        splunkd_port, self._metadata.searchinfo.splunkd_uri
                    )
                )
        except Exception as e:
            logging.error(
                'Failed to extract splunkd_port from splunkd_uri with exception="{}"'.format(
                    e
                )
            )
            splunkd_port = "8089"

        # get current user
        username = self._metadata.searchinfo.username

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-risk-superhandler",
            port=splunkd_port,
            token=session_key,
        )

        # Check if the lookup file exists

        csv_dict_file = os.path.join(splunkhome, "etc", "apps", self.uc_lookup_path)
        logging.debug('uc_lookup_path="{}"'.format(self.uc_lookup_path))
        logging.debug(
            'Attempting to read the csv_dict from file="{}"'.format(csv_dict_file)
        )

        # Check if the lookup file exists
        if not os.path.isfile(csv_dict_file):
            logging.error(
                'The uc_lookup_path="{}" was provided as part of the arguments, but this file does not exist or is not readable'.format(
                    csv_dict_file
                )
            )
            sys.exit(1)

        #################################################################
        # Loop through the records and proceed
        # The custom command does not alter the original search results #
        #################################################################

        # boolean used to define if the final action should be executed
        run_riskcollect = False

        # boolean used to define if we shall start the risk process
        start_riskprocess = False

        # Mandatory risk fields, if these exists in the records, these will always be taken into account
        risk_fields_mandatory = [
            "_time",
            "risk_object",
            "risk_object_type",
            "risk_score",
            "threat_object",
            "threat_object_type",
        ]

        # Write to a tempfile
        # Get tempdir
        tempdir = os.path.join(splunkhome, "etc", "apps", "TA-risk-superhandler", "tmp")
        if not os.path.isdir(tempdir):
            os.mkdir(tempdir)

        results_json = tempfile.NamedTemporaryFile(
            mode="w+t",
            prefix="splunk_alert_results_" + str(time.time()) + "_test_",
            suffix=".json",
            dir=tempdir,
            delete=False,
        )

        all_new_records = []

        for record in records:
            # our original record, preserved
            orig_record = record

            # We do not touch the raw events, let's render again
            # get time, if any
            has_time = None
            try:
                has_time = orig_record["_time"]
            except Exception as e:
                has_time = None

            # get all other fields

            # create a final record
            yield_record = {}

            # loop through the dict
            for k in orig_record:
                # This debug is very noisy
                # logging.debug("field=\"{}\"".format(k))

                # if not our input field, and not _time
                if k != "_time":
                    yield_record[k] = orig_record[k]

            # if time was defined, add it
            if has_time:
                yield_record["_time"] = orig_record["_time"]

            # yield
            logging.debug('orig_record="{}"'.format(yield_record))
            yield yield_record

            # Our new record dict
            new_record = record

            # log debug
            logging.debug('record="{}"'.format(json.dumps(record)))

            # Get the search_name
            try:
                search_name = record["search_name"]
            except Exception as e:
                search_name = "Adhoc risk"
                new_record["search_name"] = search_name

            ########################

            ########################
            # RISK OPERATION START #
            ########################

            ########################

            # At this stage, nothing that would fail should impact the use cases
            # In case failure, log properly the exception without interrumpting the search process

            try:
                # Extract the use case ref
                try:
                    uc_ref = record[self.uc_ref_field]
                    logging.debug('uc_ref="{}"'.format(uc_ref))
                    start_riskprocess = True

                except Exception as e:
                    logging.error(
                        'failed to retrieve the uc_ref using requested field="{}" from the upstream results, record="{}"'.format(
                            self.uc_ref_field, json.dumps(record)
                        )
                    )
                    start_riskprocess = False

                # only continue from here if the condition was satisfied
                if start_riskprocess:
                    ####################
                    # Get the JSON dict
                    ####################

                    # Start
                    jsonDict = None
                    jsonObj = None

                    # This dict will be used to be provided to the risk command
                    jsonEmptyDict = []

                    # Open the csv lookup
                    csv_file = open(csv_dict_file, "r")
                    readCSV = csv.DictReader(
                        csv_file, delimiter=str(","), quotechar=str('"')
                    )

                    # log
                    logging.debug('csv_data="{}"'.format(readCSV))

                    # Loop
                    for row in readCSV:
                        # log
                        logging.debug('In lookup row="{}"'.format(row))
                        logging.debug(
                            'In lookup looking for match with ref="{}"'.format(
                                record[self.uc_ref_field]
                            )
                        )
                        logging.debug(
                            'In lookup content uc_ref_field="{}"'.format(
                                row[self.uc_ref_field]
                            )
                        )
                        logging.debug(
                            'In lookup content json_dict="{}"'.format(row["json_dict"])
                        )
                        logging.debug(
                            "if {} is equal to {}".format(
                                row[self.uc_ref_field], record[self.uc_ref_field]
                            )
                        )

                        if row[self.uc_ref_field] == record[self.uc_ref_field]:
                            logging.info(
                                'uc_ref="{}", use case lookup record found, row="{}"'.format(
                                    record[self.uc_ref_field], json.dumps(row)
                                )
                            )
                            jsonDict = row["json_dict"]
                            run_riskcollect = True
                            break

                    # process if we have a JSON rule object
                    if not jsonDict:
                        logging.info(
                            'No lookup record match for use case uc_ref="{}", risk event creation will not be actioned'.format(
                                record[self.uc_ref_field]
                            )
                        )
                        run_riskcollect = False

                    else:
                        # Attempt to load the json dict as a Python object
                        try:
                            jsonObj = json.loads(jsonDict)
                            logging.info(
                                'record match for use case uc_ref="{}", risk_rules were loaded successfully, jsonObj="{}"'.format(
                                    record[self.uc_ref_field], json.dumps(jsonObj)
                                )
                            )
                        except Exception as e:
                            logging.error(
                                'Failure to load the json object, use case uc_ref="{}", exception="{}"'.format(
                                    record[self.uc_ref_field], e
                                )
                            )
                            run_riskcollect = False

                        # Load each JSON within the JSON array
                        # Add the very beginning of our pseudo event

                        # Allow the search_name to be set as part the JSON object
                        # If this is the case, this will override the previously set search_name value
                        json_search_name = None
                        for jsonSubObj in jsonObj:
                            try:
                                json_search_name = jsonSubObj["search_name"]
                            except Exception as e:
                                logging.debug(
                                    "No search_name was provided in the JSON object"
                                )

                        # Hande the threat, will be added to the JSON object submitted in the risk param

                        # Store type of object in a list
                        threat_objects_list = []
                        threat_objects_type_list = []

                        # optionally, handle a fields allowlist, if provided in the JSON object
                        # only fields part of these will be taken into account in the risk event generated
                        risk_fields_allowlist = None

                        for jsonSubObj in jsonObj:
                            json_risk_object = None
                            json_threat_object = None

                            try:
                                risk_object = jsonSubObj["risk_object"]
                                risk_object_type = jsonSubObj["risk_object_type"]
                                risk_score = jsonSubObj["risk_score"]
                                risk_message = jsonSubObj["risk_message"]
                                json_risk_object = True
                            except Exception as e:
                                logging.debug(
                                    'No risk object in jsonSubObj="{}"'.format(
                                        jsonSubObj
                                    )
                                )
                                json_risk_object = None

                            try:
                                # Handle threat_object_field
                                threat_object_field = jsonSubObj["threat_object_field"]
                                logging.debug(
                                    'threat_object_field="{}"'.format(
                                        threat_object_field
                                    )
                                )

                                # The threat_object value can be provided in 3 options:
                                # - as a single value
                                # - in a mv structured (__mv_risk_object)
                                # - in a native list
                                # - in a pseudo mv structured to be expanded, via a string delimiter

                                # Allow a field to be provided as part of an mv structure by submitting a delimiter, if no delimiter assume the field is a regular
                                # single value
                                try:
                                    format_separator_threat_object = jsonSubObj[
                                        "format_separator"
                                    ]
                                    logging.debug(
                                        'threat_object is specified as a potential multivalue field with a custom separator format_separator="{}"'.format(
                                            format_separator_threat_object
                                        )
                                    )
                                except Exception as e:
                                    format_separator_threat_object = None

                                # check an mv field exist for this
                                threat_object_mv_field = []
                                try:
                                    threat_object_mv_field = cim_actions.parse_mv(
                                        record["__mv_" + str(threat_object_field)]
                                    )
                                    logging.debug(
                                        'threat_object is an mv field, threat_object_mv_field="{}"'.format(
                                            threat_object_mv_field
                                        )
                                    )

                                except Exception as e:
                                    logging.debug(
                                        'threat_object_field was not found in a mv format, exception="{}"'.format(
                                            e
                                        )
                                    )

                                # fields allow list, this option would be stored a comma seperated list of fields with the key fields_allowlist
                                try:
                                    risk_fields_allowlist = jsonSubObj[
                                        "risk_fields_allowlist"
                                    ]
                                    # convert from comma seperatd list of fields to a list
                                    risk_fields_allowlist = risk_fields_allowlist.split(
                                        ","
                                    )
                                    # for each field in the mandatory list of fields, include the fields into this list if not already present
                                    for field in risk_fields_mandatory:
                                        if field not in risk_fields_allowlist:
                                            risk_fields_allowlist.append(field)

                                    logging.debug(
                                        'risk_fields_allowlist is specified as a potential multivalue field with a custom separator format_separator="{}"'.format(
                                            risk_fields_allowlist
                                        )
                                    )
                                except Exception as e:
                                    risk_fields_allowlist = None

                                # Handle all options

                                # check if it is a standard single value field
                                if (
                                    not format_separator_threat_object
                                    and len(threat_object_mv_field) == 0
                                    and type(record[threat_object_field]) != list
                                ):
                                    # log
                                    logging.debug(
                                        'the threat_object format is a single value field, threat_object="{}"'.format(
                                            record[threat_object_field]
                                        )
                                    )

                                    # check blocklist
                                    if (
                                        record[threat_object_field]
                                        in blocklist_threat_object_patterns
                                    ):
                                        logging.warn(
                                            'blocklist: the threat_object="{}" is not allowed as per blocklist_threat_object_patterns="{}"'.format(
                                                record[risk_object],
                                                blocklist_threat_object_patterns,
                                            )
                                        )

                                    else:
                                        # append to our list
                                        threat_objects_list.append(
                                            record[threat_object_field]
                                        )

                                else:
                                    logging.debug(
                                        "the threat_object format is a multivalue format"
                                    )

                                    # check if it is an mvfield
                                    if len(threat_object_mv_field) > 0:
                                        for sub_threat_object in threat_object_mv_field:
                                            threat_objects_list.append(
                                                sub_threat_object
                                            )

                                    # check if it is a native list
                                    elif type(record[threat_object_field]) == list:
                                        for sub_threat_object in record[
                                            threat_object_field
                                        ]:
                                            threat_objects_list.append(
                                                sub_threat_object
                                            )

                                    # check if a custom format delimiter is set
                                    elif format_separator_threat_object:
                                        try:
                                            threat_objects_list = record[
                                                threat_object_field
                                            ].split(format_separator_threat_object)
                                            logging.debug(
                                                'uc_ref="{}", successfully loaded the threat_object field as a custom separated format using format_separator="{}"'.format(
                                                    record[self.uc_ref_field],
                                                    format_separator_threat_object,
                                                )
                                            )
                                        except Exception as e:
                                            threat_objects_list = record[
                                                threat_object_field
                                            ]
                                            logging.error(
                                                'uc_ref="{}", could not load the field="{}" as a format separated field, the rule definition is likely incorrect, exception="{}"'.format(
                                                    record[self.uc_ref_field],
                                                    threat_object_field,
                                                    str(e),
                                                )
                                            )

                                # Add to the record
                                new_record["threat_object"] = threat_objects_list

                                # check blocklist (remove from list if blocklisted)
                                for threat_object in threat_objects_list:
                                    if (
                                        threat_object
                                        in blocklist_threat_object_patterns
                                    ):
                                        logging.warn(
                                            'blocklist: the threat_object="{}" is not allowed as per blocklist_threat_object_patterns="{}"'.format(
                                                threat_object,
                                                blocklist_threat_object_patterns,
                                            )
                                        )
                                        threat_objects_list.remove(threat_object)

                                # Handle threat_object_type
                                threat_object_type = jsonSubObj["threat_object_type"]
                                logging.debug(
                                    'threat_object_type="{}"'.format(threat_object_type)
                                )
                                threat_objects_type_list.append(threat_object_type)
                                logging.debug(
                                    'threat_objects_type_list="{}"'.format(
                                        threat_objects_type_list
                                    )
                                )

                                # Add
                                new_record[
                                    "threat_object_type"
                                ] = threat_objects_type_list

                                # Boolean
                                json_threat_object = True

                            except Exception as e:
                                logging.debug(
                                    'No threat object in jsonSubObj="{}"'.format(
                                        jsonSubObj
                                    )
                                )
                                json_threat_object = None

                            # Add
                            if json_risk_object:
                                jsonEmptyDict.append(
                                    {
                                        "risk_object_field": risk_object,
                                        "risk_object_type": risk_object_type,
                                        "risk_score": risk_score,
                                        "risk_message": risk_message,
                                    }
                                )
                            elif json_threat_object:
                                jsonEmptyDict.append(
                                    {
                                        "threat_object_field": threat_object_field,
                                        "threat_object_type": threat_object_type,
                                    }
                                )

                        # log debug
                        logging.debug(
                            'jsonEmptyDict="{}"'.format(json.dumps(jsonEmptyDict))
                        )

                        # override if any
                        if json_search_name:
                            search_name = json_search_name
                            logging.debug(
                                'search_name was overriden via the JSON dictionnary, search_name="{}"'.format(
                                    search_name
                                )
                            )

                        # Lookup through the dict again and proceed
                        for jsonSubObj in jsonObj:
                            logging.debug(
                                'jsonSubObj="{}"'.format(
                                    json.dumps(jsonSubObj, indent=1)
                                )
                            )

                            # Handle if the JSON object contains a risk rule
                            jsonSubObjHasRisk = None

                            try:
                                risk_object = jsonSubObj["risk_object"]
                                jsonSubObjHasRisk = True
                            except Exception as e:
                                jsonSubObjHasRisk = None
                                logging.debug(
                                    'jsonSubObj="{}" does not include a risk JSON dictionnary'.format(
                                        json.dumps(jsonSubObj, indent=1)
                                    )
                                )

                            # Loop if we have a JSON risk rule
                            if jsonSubObjHasRisk:
                                # for each JSON rule, apply the risk - magic
                                risk_object = jsonSubObj["risk_object"]
                                risk_object_type = jsonSubObj["risk_object_type"]
                                risk_score = jsonSubObj["risk_score"]
                                risk_message = jsonSubObj["risk_message"]

                                # if a risk_score is defined in the event already, this should override the JSON rule, as per OOTB Risk alert behaviour
                                try:
                                    event_risk_score = float(record.get("risk_score"))
                                    if event_risk_score:
                                        logging.info(
                                            "A value for risk_score of {} was found in the event, this will override the JSON definition".format(
                                                event_risk_score
                                            )
                                        )
                                        risk_score = event_risk_score

                                except Exception as e:
                                    logging.debug(
                                        "There are no risk_score value defined at the event level"
                                    )

                                # Verify that the risk_object field exists, and proceed
                                risk_object_value = None
                                try:
                                    risk_object_value = record[risk_object]
                                except Exception as e:
                                    logging.error(
                                        'uc_ref="{}", cannot extract the risk_object="{}", the field does not exist and will be ignored, record="{}"'.format(
                                            record[self.uc_ref_field],
                                            risk_object,
                                            json.dumps(record),
                                        )
                                    )

                                if risk_object_value:
                                    # Allow a field to be provided as part of an mv structure by submitting a delimiter, if no delimiter assume the field is a regular
                                    # single value
                                    try:
                                        format_separator = jsonSubObj[
                                            "format_separator"
                                        ]
                                    except Exception as e:
                                        format_separator = None

                                    # log
                                    logging.info(
                                        'risk rule loaded, uc_ref="{}", risk_object="{}", risk_object_type="{}", risk_score="{}", risk_message="{}", format_field="{}"'.format(
                                            record[self.uc_ref_field],
                                            risk_object,
                                            risk_object_type,
                                            risk_score,
                                            risk_message,
                                            format_separator,
                                        )
                                    )

                                    # Execute a single search for optimisation purposes

                                    # The risk_object value can be provided in 3 options:
                                    # - as a single value
                                    # - in a mv structured (__mv_risk_object)
                                    # - in a native list
                                    # - in a pseudo mv structured to be expanded, via a string delimiter

                                    # check an mv field exist for this
                                    risk_object_mv_field = []
                                    try:
                                        risk_object_mv_field = cim_actions.parse_mv(
                                            record["__mv_" + str(risk_object)]
                                        )
                                        logging.debug(
                                            'risk_object is an mv field, risk_object_mv_field="{}"'.format(
                                                risk_object_mv_field
                                            )
                                        )

                                    except Exception as e:
                                        logging.debug(
                                            'risk_object was not found in a mv format, exception="{}"'.format(
                                                e
                                            )
                                        )

                                    #
                                    # risk object
                                    #

                                    # handle the format field
                                    if (
                                        not format_separator
                                        and len(risk_object_mv_field) == 0
                                        and type(record[risk_object]) != list
                                    ):
                                        # check blocklist
                                        if (
                                            record[risk_object]
                                            in blocklist_risk_object_patterns
                                        ):
                                            logging.warn(
                                                'blocklist: the risk_object="{}" is not allowed as per blocklist_risk_object_patterns="{}"'.format(
                                                    record[risk_object],
                                                    blocklist_risk_object_patterns,
                                                )
                                            )

                                        else:
                                            # log
                                            logging.debug(
                                                'the risk object format is a single value field, risk_object="{}"'.format(
                                                    risk_object
                                                )
                                            )

                                            # Add
                                            new_record["risk_object"] = record[
                                                risk_object
                                            ]
                                            new_record[
                                                "risk_object_type"
                                            ] = risk_object_type
                                            new_record["risk_score"] = risk_score
                                            new_record["risk_message"] = risk_message

                                            # log
                                            logging.debug(
                                                'before adding the risk, risk_object="{}", risk_object_type="{}", risk_score="{}", risk_message="{}"'.format(
                                                    record[risk_object],
                                                    risk_object_type,
                                                    risk_score,
                                                    risk_message,
                                                )
                                            )

                                            # Handle this mv structure in a new record
                                            mv_record = {}
                                            for k in new_record:
                                                mv_record[k] = new_record[k]
                                            logging.debug(
                                                'mv_record="{}"'.format(mv_record)
                                            )

                                            # Add
                                            mv_record["risk_object"] = record[
                                                risk_object
                                            ]
                                            mv_record[
                                                "risk_object_type"
                                            ] = risk_object_type
                                            mv_record["risk_score"] = risk_score
                                            mv_record["risk_message"] = risk_message

                                            # Add original fields
                                            for k in record:
                                                if not k.startswith("__mv"):
                                                    # if a risk_fields_allowlist was provided, only include the fields part of this list
                                                    if risk_fields_allowlist:
                                                        if k in risk_fields_allowlist:
                                                            mv_record[k] = record[k]
                                                    else:
                                                        mv_record[k] = record[k]

                                            # Add to final records
                                            all_new_records.append(mv_record)

                                    else:
                                        logging.debug(
                                            "the risk object format is a multivalue format"
                                        )

                                        # if from an __mv_risk_object field
                                        if len(risk_object_mv_field) > 0:
                                            risk_object_list = risk_object_mv_field

                                        # or via the separator in single value string separated
                                        elif (
                                            format_separator
                                            and type(record[risk_object]) != list
                                        ):
                                            try:
                                                risk_object_list = record[
                                                    risk_object
                                                ].split(format_separator)
                                                logging.debug(
                                                    'uc_ref="{}", successfully loaded the risk_object field as a custom separated format using format_separator="{}"'.format(
                                                        record[self.uc_ref_field],
                                                        format_separator,
                                                    )
                                                )

                                            except Exception as e:
                                                risk_object_list = record[risk_object]
                                                logging.error(
                                                    'uc_ref="{}", could not load the field="{}" as a format separated field, the rule definition is likely incorrect, exception="{}"'.format(
                                                        record[self.uc_ref_field],
                                                        risk_object,
                                                        str(e),
                                                    )
                                                )

                                        # stored in a native list
                                        else:
                                            # if the format separator was incorrectly set, generate a warning message
                                            if format_separator:
                                                logging.warn(
                                                    'uc_ref="{}", the risk_object="{}" has a format_separator="{}" but it comes as a multivalue field instead, this configuration is likely incorrect'.format(
                                                        record[self.uc_ref_field],
                                                        risk_object,
                                                        format_separator,
                                                    )
                                                )

                                            # store
                                            risk_object_list = record[risk_object]

                                        for risk_subobject in risk_object_list:
                                            # check block list
                                            if (
                                                risk_subobject
                                                in blocklist_risk_object_patterns
                                            ):
                                                logging.warn(
                                                    'blocklist: the risk_object="{}" is not allowed as per blocklist_risk_object_patterns="{}"'.format(
                                                        risk_subobject,
                                                        blocklist_risk_object_patterns,
                                                    )
                                                )

                                            else:
                                                if risk_subobject:
                                                    logging.debug(
                                                        'run the risk action against risk_subobject="{}"'.format(
                                                            risk_subobject
                                                        )
                                                    )

                                                    # Handle this mv structure in a new record
                                                    mv_record = {}
                                                    for k in new_record:
                                                        mv_record[k] = new_record[k]
                                                    log.debug(
                                                        'mv_record="{}"'.format(
                                                            mv_record
                                                        )
                                                    )

                                                    # Add
                                                    mv_record[
                                                        "risk_object"
                                                    ] = risk_subobject
                                                    mv_record[
                                                        "risk_object_type"
                                                    ] = risk_object_type
                                                    mv_record["risk_score"] = risk_score
                                                    mv_record[
                                                        "risk_message"
                                                    ] = risk_message

                                                    # Add original fields
                                                    for k in record:
                                                        if not k.startswith("__mv"):
                                                            # if a risk_fields_allowlist was provided, only include the fields part of this list
                                                            if risk_fields_allowlist:
                                                                if (
                                                                    k
                                                                    in risk_fields_allowlist
                                                                ):
                                                                    mv_record[
                                                                        k
                                                                    ] = record[k]
                                                            else:
                                                                mv_record[k] = record[k]

                                                    # Add to final records
                                                    all_new_records.append(mv_record)

            # Initial exception handler
            except Exception as e:
                logging.error(
                    'An exception was encountered while processing the risk actions, exception="{}"'.format(
                        e
                    )
                )

            # Add all fields from the record, except __mv structure
            for k in record:
                if not k.startswith("__mv"):
                    new_record[k] = record[k]

        # if this option is set
        if self.uc_svc_account:
            if username != self.uc_svc_account:
                logging.info(
                    'The service account option was set to="{}" and doesn\'t match the current user space="{}", risk events will not be generated'.format(
                        self.uc_svc_account, username
                    )
                )
                run_riskcollect = False

        # Additional safety: if none of the expected fields in the Risk definition could be found (the JSON definition is incorrect or the event unexpected)
        # Don't run the rest of the logic

        if not all_new_records:
            logging.debug(
                "Not triggering any action, all risk objects failed to be extracted, please verify the event and the risk definition."
            )
            run_riskcollect = False

        # Shall we proceed
        if run_riskcollect:
            #
            # Write final json
            #

            # Write our json record
            results_json.writelines(json.dumps(all_new_records))
            results_json.seek(0)

            logging.debug('content of results_json="{}"'.format(all_new_records))

            #
            # Set and run a Splunk query using the Python SDK
            #

            splQuery = (
                '| riskjsonload json_path="'
                + results_json.name
                + '" \n'
                + '| eval search_name="'
                + str(search_name)
                + '"\n'
                + "| expandtoken"
                + "\n"
                + "| eval _key=search_name | lookup local=true correlationsearches_lookup _key OUTPUTNEW annotations, description as savedsearch_description | spathannotations"
                + '| collectrisk search_name="'
                + str(search_name)
                + '"'
            )

            logging.debug('splQuery="{}"'.format(splQuery))

            # Run a search in Python
            kwargs_search = {
                "app": "TA-risk-superhandler",
                "earliest_time": "-5m",
                "latest_time": "now",
                "output_mode": "json",
            }

            try:
                # spawn the search and get the results
                searchresults = service.jobs.oneshot(splQuery, **kwargs_search)
                reader = results.JSONResultsReader(searchresults)

                for item in reader:
                    query_result = item
                logging.info(
                    'risk command was successful, result="{}"'.format(
                        json.dumps(query_result, indent=0)
                    )
                )

            except Exception as e:
                logging.error('risk command has failed with exception="{}"'.format(e))

            finally:
                # close the json
                results_json.close()

                # delete
                if os.path.isfile(results_json.name):
                    try:
                        os.remove(results_json.name)
                    except Exception as e:
                        logging.error(
                            'Failure to remove temporary file, path="{}", exception="{}"'.format(
                                results_json.name, e
                            )
                        )

        # ensure not to leave a file on the file-system
        else:
            # delete
            if os.path.isfile(results_json.name):
                try:
                    os.remove(results_json.name)
                except Exception as e:
                    logging.error(
                        'Failure to remove temporary file, path="{}", exception="{}"'.format(
                            results_json.name, e
                        )
                    )


dispatch(RiskSuperHandler, sys.argv, sys.stdin, sys.stdout, __name__)
