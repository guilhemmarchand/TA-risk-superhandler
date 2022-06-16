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
from collections import OrderedDict
import ast
import csv
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/risk_superhandler.log", 'a')
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
class RiskSuperHandler(StreamingCommand):

    json_dict = Option(
        doc='''
        **Syntax:** **The json risk dictionnary****
        **Description:** JSON dict.''',
        require=False, validate=validators.Match("json_dict", r"^.*$"))

    uc_lookup_path = Option(
        doc='''
        **Syntax:** **The dictionnary lookup path****
        **Description:** use case reference lookup path.''',
        require=False, validate=validators.Match("uc_lookup_path", r"^.*$"))

    uc_ref_field = Option(
        doc='''
        **Syntax:** **The name of the field containing the use case reference****
        **Description:** use case reference field name.''',
        require=True, validate=validators.Match("uc_ref_field", r"^.*$"))

    # status will be statically defined as imported

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

        # To trace all attr
        #logging.debug("Trace all meta")
        #logging.debug(vars(self))
        #logging.debug(vars(confs))
        #logging.debug(vars(stanza))
        #logging.debug(dir())
        #logging.debug("name is=\"{}\"".format(self.name))

        # one of the two arguments is mandatory
        if not self.json_dict and not self.uc_lookup_path:
            logging.error("Invalid argument were provided, either the json_dict with the JSON dictionnary, or uc_lookup_path must be provided")
            yield {"_time": time.time(), "response": "Invalid argument were provided, either the json_dict with the JSON dictionnary, or uc_lookup_path must be provided"}
            sys.exit(0) # exit 0 to allow yield of the output above

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                        namespace='TA-risk-superhandler', sessionKey=session_key, owner='-')
        mydict = entity
        splunkd_port = mydict['mgmtHostPort']

        # Splunk header
        splunk_headers = {
        'Authorization': 'Splunk %s' % session_key,
        'Content-Type': 'application/json'}

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-risk-superhandler",
            port=splunkd_port,
            token=session_key
        )

        # Loop in the results

        # If provided as part of a lookup
        if self.uc_lookup_path:
            csv_dict_file = os.path.join(splunkhome, "etc", "apps", self.uc_lookup_path)
            logging.debug("uc_lookup_path=\"{}\"".format(self.uc_lookup_path))
            logging.debug("Attempting to read the csv_dict from file=\"{}\"".format(csv_dict_file))

            # Check if the lookup file exists
            if not os.path.isfile(csv_dict_file):
                logging.error("The uc_lookup_path=\"{}\" was provided as part of the arguments, but this file does not exist or is not readable".format(csv_dict_file))

        # If the JSON dictionnary is provided as an argument to the custom command        
        elif self.json_dict:
            jsonDict = str(self.json_dict)
            logging.debug("json_dict=\"{}\"".format(jsonDict))

            # Attempt to load the json dict as a Python object
            try:
                jsonObj = json.loads(jsonDict)
                logging.debug("jsonObj was loaded successfully")
            except Exception as e:
                logging.error("Failure to load the json object with exception=\"{}\"".format(e))

        #################################################################
        # Loop through the records and proceed
        # The custom command does not alter the original search results #    
        #################################################################

        for record in records:

            # log debug
            logging.debug("record=\{}\"".format(record))

            # To be recycled in the next phases
            orig_raw = json.dumps(record)

            # Get the search_name
            try:
                search_name = record['search_name']
            except Exception as e:
                search_name = "Adhoc risk"

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
                    logging.debug("uc_ref=\"{}\"".format(uc_ref))
                except Exception as e:
                    logging.error("failed to retrieve the uc_ref from the upstream results")

                ####################        
                # Get the JSON dict
                ####################

                # Start     
                jsonDict = None

                # This dict will be used to be provided to the risk command
                jsonEmptyDict = []

                if self.uc_lookup_path:

                    # Open the csv lookup
                    csv_file = open(csv_dict_file, "r")
                    readCSV = csv.DictReader(csv_file, delimiter=str(u','), quotechar=str(u'"'))

                    # log
                    logging.debug("csv_data=\"{}\"".format(readCSV))

                    # Loop
                    for row in readCSV:

                        # log
                        logging.debug("In lookup row=\"{}\"".format(row))
                        logging.debug("In lookup looking for match with ref=\"{}\"".format(record[self.uc_ref_field]))
                        logging.debug("In lookup content uc_ref_field=\"{}\"".format(row[self.uc_ref_field]))
                        logging.debug("In lookup content json_dict=\"{}\"".format(row['json_dict']))

                        logging.debug("if {} is equal to {}".format(row[self.uc_ref_field], record[self.uc_ref_field]))

                        if row[self.uc_ref_field] == record[self.uc_ref_field]:
                            logging.debug("In lookup record found, row=\"{}\"".format(row))
                            jsonDict = row['json_dict']

                # else if get from argument
                elif self.json_dict:
                    jsonDict = str(self.json_dict)
                    logging.info("json_dict=\"{}\"".format(jsonDict))

                # process if we have a JSON rule object
                if not jsonDict:
                    logging.info("No lookup record match for use case uc_ref_field=\"{}\", risk event creation will not be actioned".format(record[self.uc_ref_field]))

                else:
                    # Attempt to load the json dict as a Python object
                    try:
                        jsonObj = json.loads(jsonDict)
                        logging.info("record match for use case uc_ref_field=\"{}\", risk_rules were loaded successfully, jsonObj=\"{}\"".format(record[self.uc_ref_field], json.dumps(jsonObj)))
                    except Exception as e:
                        logging.error("Failure to load the json object, use case uc_ref_field=\"{}\", exception=\"{}\"".format(record[self.uc_ref_field], e))

                    #
                    # Set the search basis
                    #
                    
                    splQueryRoot = "| makeresults | eval _raw=\"" + orig_raw.replace('\"', '\\\"') + "\" | spath | fields - _raw"
                    splQuery = ""
                    spl_count = 1                    

                    # Load each JSON within the JSON array
                    # Add the very beginning of our pseudo event

                    # Allow the search_name to be set as part the JSON object
                    # If this is the case, this will override the previously set search_name value
                    json_search_name = None
                    for jsonSubObj in jsonObj:
                        try:
                            json_search_name = jsonSubObj['search_name']
                        except Exception as e:
                            logging.debug("No search_name was provided in the JSON object")

                    # Hande the threat, will be added to the JSON object submitted in the risk param

                    # for es64 compatibility purposes, store type of object in a list
                    threat_objects_list = []
                    threat_objects_type_list = []

                    for jsonSubObj in jsonObj:
                        json_risk_object = None
                        json_threat_object = None

                        try:
                            risk_object = jsonSubObj['risk_object']
                            risk_object_type = jsonSubObj['risk_object_type']
                            risk_score = jsonSubObj['risk_score']
                            risk_message = jsonSubObj['risk_message']
                            json_risk_object = True
                        except Exception as e:
                            logging.debug("No risk object in jsonSubObj=\"{}\"".format(jsonSubObj))
                            json_risk_object = None

                        try:
                            threat_object_field = jsonSubObj['threat_object_field']
                            threat_objects_list.append(record[threat_object_field])
                            logging.debug("threat_objects_list=\"{}\"".format(threat_objects_list))
                            threat_object_type = jsonSubObj['threat_object_type']
                            threat_objects_type_list.append(threat_object_type)
                            logging.debug("threat_objects_type_list=\"{}\"".format(threat_objects_type_list))
                            json_threat_object = True
                        except Exception as e:
                            logging.debug("No threat object in jsonSubObj=\"{}\"".format(jsonSubObj))
                            json_threat_object = None

                        # Add
                        if json_risk_object:
                            jsonEmptyDict.append({'risk_object_field': risk_object, 'risk_object_type': risk_object_type, 'risk_score': risk_score, 'risk_message': risk_message})
                        elif json_threat_object:
                            jsonEmptyDict.append({'threat_object_field': threat_object_field, 'threat_object_type': threat_object_type})

                            # In addition, add the field/value to the root search
                            #splQueryRoot = splQueryRoot + "\n" +\
                            #    "| eval threat_object=\"" + record[threat_object_field] + "\", threat_object_type=\"" + threat_object_field + "\""

                    # log debug
                    logging.debug("jsonEmptyDict=\"{}\"".format(json.dumps(jsonEmptyDict)))

                    # override if any
                    if json_search_name:
                        search_name = json_search_name
                        logging.debug("search_name was overriden via the JSON dictionnary, search_name=\"{}\"".format(search_name))

                    # Lookup through the dict again and proceed
                    for jsonSubObj in jsonObj:
                        logging.debug("jsonSubObj=\"{}\"".format(json.dumps(jsonSubObj, indent=1)))

                        # Handle if the JSON object contains a risk rule
                        jsonSubObjHasRisk = None

                        try:
                            risk_object = jsonSubObj['risk_object']
                            jsonSubObjHasRisk = True
                        except Exception as e:
                            jsonSubObjHasRisk = None
                            logging.debug("jsonSubObj=\"{}\" does not include a risk JSON dictionnary".format(json.dumps(jsonSubObj, indent=1)))

                        # Loop if we have a JSON risk rule
                        if jsonSubObjHasRisk:

                            # for each JSON rule, apply the risk - magic
                            risk_object = jsonSubObj['risk_object']
                            risk_object_type = jsonSubObj['risk_object_type']
                            risk_score = jsonSubObj['risk_score']
                            risk_message = jsonSubObj['risk_message']

                            # Allow a field to be provided as part of an mv structure by submitting a delimiter, if no delimiter assume the field is a regular
                            # single value
                            try:
                                format_separator = jsonSubObj['format_separator']
                            except Exception as e:
                                format_separator = None

                            # log
                            logging.info("risk rule loaded, risk_object=\"{}\", risk_object_type=\"{}\", risk_score=\"{}\, risk_message=\"{}\", format_field=\"{}\"".format(risk_object, risk_object_type, risk_score, risk_message, format_separator))

                            # Execute a single search for optimisation purposes

                            # handle the format field
                            if not format_separator:

                                # log
                                logging.debug("the risk object format is a single value field, risk_object=\"{}\"".format(risk_object))

                                # Set the initial query
                                if spl_count>1:
                                    splQuery = str(splQuery) + "\n" +\
                                        "| append [ \n" + str(splQueryRoot) + "\n" +\
                                        "| eval risk_object=\"" + str(risk_object) + "\", risk_object_type=\"" + str(risk_object_type)+ "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                        "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken ]\n"
                                else:
                                    splQuery = str(splQueryRoot) + "\n" +\
                                        "| eval risk_object=\"" + str(risk_object) + "\", risk_object_type=\"" + str(risk_object_type) + "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                        "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken\n"
                                spl_count+=1

                                # If running in pre threat compatible mode, force include the threat_object and threat_object_type fields
                                if len(threat_objects_list) and len(threat_objects_type_list):
                                    threat_objects_str = "|".join(threat_objects_list)
                                    threat_objects_type_str = "|".join(threat_objects_type_list)
                                    splQuery = splQuery + "\n" +\
                                        "| eval threat_object=\"" + threat_objects_str +\
                                        "\", threat_object_type=\"" + threat_objects_type_str + "\" | makemv delim=\"|\" threat_object | makemv delim=\"|\" threat_object_type"

                            else:

                                logging.debug("the risk object format is a multivalue format with seperator=\"{}\"".format(format_separator))
                                risk_object_list = record[risk_object].split(format_separator)

                                for risk_subobject in risk_object_list:
                                    logging.debug("run the risk action against risk_subobject=\"{}\"".format(risk_subobject))

                                    # set the query
                                    if spl_count>1:
                                        splQuery = str(splQuery) + "\n" +\
                                            "| append [ \n" + str(splQueryRoot) + "\n" +\
                                            "| eval risk_object=\"" + str(risk_subobject) + "\", risk_object_type=\"" + str(risk_object_type) + "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                            "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken ]\n"
                                    else:
                                        splQuery = str(splQueryRoot) + "\n" +\
                                            "| eval risk_object=\"" + str(risk_subobject) + "\", risk_object_type=\"" + str(risk_object_type) + "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                            "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken\n"
                                    spl_count+=1

                                    # Manually create the threats fields (if any)
                                    if len(threat_objects_list) and len(threat_objects_type_list):
                                        threat_objects_str = "|".join(threat_objects_list)
                                        threat_objects_type_str = "|".join(threat_objects_type_list)
                                        splQuery = splQuery + "\n" +\
                                            "| eval threat_object=\"" + threat_objects_str +\
                                            "\", threat_object_type=\"" + threat_objects_type_str + "\" | makemv delim=\"|\" threat_object | makemv delim=\"|\" threat_object_type"

                    #
                    # Run the search
                    #

                    if spl_count>1:

                        jsonEmptyStr = json.dumps(jsonEmptyDict)

                        # Terminate the search
                        splQuery = str(splQuery) + "\n" +\
                            "| eval search_name=\"" + str(search_name) + "\"\n" +\
                            "| eval _key=search_name | lookup local=true correlationsearches_lookup _key OUTPUTNEW annotations, description as savedsearch_description | spathannotations" +\
                            "| collectrisk search_name=\"" + str(search_name) + "\""

                        logging.debug("splQuery=\"{}\"".format(splQuery))

                        # Run a search in Python
                        kwargs_search = {"app": "TA-risk-superhandler", "earliest_time": "-5m", "latest_time": "now"}

                        # spawn the search and get the results
                        searchresults = service.jobs.oneshot(splQuery, **kwargs_search)

                        try:
                            reader = results.ResultsReader(searchresults)
                            for item in reader:
                                query_result = item
                            logging.info("risk command was successful, result=\"{}\"".format(json.dumps(query_result, indent=0)))

                        except Exception as e:
                            logging.error("risk command has failed with exception=\"{}\"".format(e))

                    else:
                        logging.error("It looks like we don't have a proper search to run, this sounds like it is unexpected, splQuery=\"{}\"".format(splQuery))

            # Initial exception handler
            except Exception as e:
                logging.error("An exception was encountered while processing the risk actions, exception=\"{}\"".format(e))

            #
            # Final
            #

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

            # yield
            yield yield_record

dispatch(RiskSuperHandler, sys.argv, sys.stdin, sys.stdout, __name__)
