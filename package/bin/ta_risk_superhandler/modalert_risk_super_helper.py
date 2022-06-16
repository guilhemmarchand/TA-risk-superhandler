# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    uc_lookup_path = helper.get_param("uc_lookup_path")
    helper.log_info("uc_lookup_path={}".format(uc_lookup_path))

    uc_ref_field = helper.get_param("uc_ref_field")
    helper.log_info("uc_ref_field={}".format(uc_ref_field))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action risk_super started.")

    import splunk
    import splunk.entity
    import json
    import csv
    import time
    import requests
    import os, sys
    import splunklib.client as client
    from splunklib.modularinput.event import Event, ET
    from splunklib.modularinput.event_writer import EventWriter
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    splunkhome = os.environ['SPLUNK_HOME']

    sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-risk-superhandler', 'lib'))

    # import Splunk libs
    from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
    from splunklib import six
    import splunklib.client as client
    import splunklib.results as results

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key
    
    # Get splunkd port
    entity = splunk.entity.getEntity('/server', 'settings',
                                        namespace='TA-risk-superhandler', sessionKey=session_key, owner='-')
    splunkd_port = entity['mgmtHostPort']
    splunkd_host = entity['host']

    # Set header for request authentication
    header = 'Splunk ' + str(session_key)

    # get service
    service = client.connect(
        owner="nobody",
        app="trackme",
        port=splunkd_port,
        token=session_key
    )

    # Get our alert config
    uc_lookup_path = helper.get_param("uc_lookup_path")
    helper.log_info("uc_lookup_path={}".format(uc_lookup_path))

    uc_ref_field = helper.get_param("uc_ref_field")
    helper.log_info("uc_ref_field={}".format(uc_ref_field))

    # Check the CSV lookup file
    csv_dict_file = os.path.join(splunkhome, "etc", "apps", uc_lookup_path)
    helper.log_debug("uc_lookup_path=\"{}\"".format(uc_lookup_path))
    helper.log_debug("Attempting to read the csv_dict from file=\"{}\"".format(csv_dict_file))

    # Check if the lookup file exists
    if not os.path.isfile(csv_dict_file):
        helper.log_error("The uc_lookup_path=\"{}\" was provided as part of the arguments, but this file does not exist or is not readable".format(csv_dict_file))
        return 1

    # Loop through the results
    records = helper.get_events()
    for record in records:
        helper.log_debug("record={}".format(record))

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
                uc_ref = record[uc_ref_field]
                helper.log_debug("uc_ref=\"{}\"".format(uc_ref))
            except Exception as e:
                helper.log_error("failed to retrieve the uc_ref from the upstream results")

            ####################        
            # Get the JSON dict
            ####################

            # Start     
            jsonDict = None

            # This dict will be used to be provided to the risk command
            jsonEmptyDict = []

            # Open the csv lookup
            csv_file = open(csv_dict_file, "r")
            readCSV = csv.DictReader(csv_file, delimiter=str(u','), quotechar=str(u'"'))

            # log
            helper.log_debug("csv_data=\"{}\"".format(readCSV))

            # Loop
            for row in readCSV:

                # log
                helper.log_debug("In lookup row=\"{}\"".format(row))
                helper.log_debug("In lookup looking for match with ref=\"{}\"".format(record[uc_ref_field]))
                helper.log_debug("In lookup content uc_ref_field=\"{}\"".format(row[uc_ref_field]))
                helper.log_debug("In lookup content json_dict=\"{}\"".format(row['json_dict']))

                helper.log_debug("if {} is equal to {}".format(row[uc_ref_field], record[uc_ref_field]))

                if row[uc_ref_field] == record[uc_ref_field]:
                    helper.log_debug("In lookup record found, row=\"{}\"".format(row))
                    jsonDict = row['json_dict']

            # process if we have a JSON rule object
            if not jsonDict:
                helper.log_info("No lookup record match for use case uc_ref_field=\"{}\", risk event creation will not be actioned".format(record[uc_ref_field]))

            else:
                # Attempt to load the json dict as a Python object
                try:
                    jsonObj = json.loads(jsonDict)
                    helper.log_info("record match for use case uc_ref_field=\"{}\", risk_rules were loaded successfully, jsonObj=\"{}\"".format(record[uc_ref_field], json.dumps(jsonObj)))
                except Exception as e:
                    helper.log_error("Failure to load the json object, use case uc_ref_field=\"{}\", exception=\"{}\"".format(record[uc_ref_field], e))

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
                        helper.log_debug("No search_name was provided in the JSON object")

                # Hande the threat, will be added to the JSON object submitted in the risk param
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
                        helper.log_debug("No risk object in jsonSubObj=\"{}\"".format(jsonSubObj))
                        json_risk_object = None

                    try:
                        threat_object_field = jsonSubObj['threat_object_field']
                        threat_object_type = jsonSubObj['threat_object_type']
                        json_threat_object = True
                    except Exception as e:
                        helper.log_debug("No threat object in jsonSubObj=\"{}\"".format(jsonSubObj))
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
                helper.log_debug("jsonEmptyDict=\"{}\"".format(json.dumps(jsonEmptyDict)))

                # override if any
                if json_search_name:
                    search_name = json_search_name
                    helper.log_debug("search_name was overriden via the JSON dictionnary, search_name=\"{}\"".format(search_name))

                # Lookup through the dict again and proceed
                for jsonSubObj in jsonObj:
                    helper.log_debug("jsonSubObj=\"{}\"".format(json.dumps(jsonSubObj, indent=1)))

                    # Handle if the JSON object contains a risk rule
                    jsonSubObjHasRisk = None

                    try:
                        risk_object = jsonSubObj['risk_object']
                        jsonSubObjHasRisk = True
                    except Exception as e:
                        jsonSubObjHasRisk = None
                        helper.log_debug("jsonSubObj=\"{}\" does not include a risk JSON dictionnary".format(json.dumps(jsonSubObj, indent=1)))

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
                        helper.log_info("risk rule loaded, risk_object=\"{}\", risk_object_type=\"{}\", risk_score=\"{}\, risk_message=\"{}\", format_field=\"{}\"".format(risk_object, risk_object_type, risk_score, risk_message, format_separator))

                        # Execute a single search for optimisation purposes

                        # handle the format field
                        if not format_separator:

                            # log
                            helper.log_debug("the risk object format is a single value field, risk_object=\"{}\"".format(risk_object))

                            # Set the initial query
                            if spl_count>1:
                                splQuery = str(splQuery) + "\n" +\
                                    "| append [ \n" + str(splQueryRoot) + "\n" +\
                                    "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken ]\n"
                            else:
                                splQuery = str(splQueryRoot) + "\n" +\
                                    "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken\n"
                            spl_count+=1

                        else:

                            helper.log_debug("the risk object format is a multivalue format with seperator=\"{}\"".format(format_separator))
                            risk_object_list = record[risk_object].split(format_separator)

                            for risk_subobject in risk_object_list:
                                helper.log_debug("run the risk action against risk_subobject=\"{}\"".format(risk_subobject))

                                # set the query
                                if spl_count>1:
                                    splQuery = str(splQuery) + "\n" +\
                                        "| append [ \n" + str(splQueryRoot) + "\n" +\
                                        "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken ]\n"
                                else:
                                    splQuery = str(splQueryRoot) + "\n" +\
                                        "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken\n"
                                spl_count+=1

                #
                # Run the search
                #

                if spl_count>1:

                    jsonEmptyStr = json.dumps(jsonEmptyDict)

                    # Terminate the search
                    splQuery = str(splQuery) + "\n" +\
                        "| eval search_name=\"" + str(search_name) + "\"\n" +\
                        "| eval _key=search_name | lookup local=true correlationsearches_lookup _key OUTPUTNEW annotations, description as savedsearch_description | spathannotations" +\
                        "| collectrisk search_name=\"" + str(search_name) + "\" risk=\"" + jsonEmptyStr.replace("\"", "\\\"") + "\""

                    helper.log_debug("splQuery=\"{}\"".format(splQuery))

                    # Run a search in Python
                    kwargs_search = {"app": "TA-risk-superhandler", "earliest_time": "-5m", "latest_time": "now"}

                    # spawn the search and get the results
                    searchresults = service.jobs.oneshot(splQuery, **kwargs_search)

                    try:
                        reader = results.ResultsReader(searchresults)
                        for item in reader:
                            query_result = item
                        helper.log_info("risk command was successful, result=\"{}\"".format(json.dumps(query_result, indent=0)))

                    except Exception as e:
                        helper.log_error("risk command has failed with exception=\"{}\"".format(e))

                else:
                    helper.log_error("It looks like we don't have a proper search to run, this sounds like it is unexpected, splQuery=\"{}\"".format(splQuery))

        # Initial exception handler
        except Exception as e:
            helper.log_error("An exception was encountered while processing the risk actions, exception=\"{}\"".format(e))

    return 0
