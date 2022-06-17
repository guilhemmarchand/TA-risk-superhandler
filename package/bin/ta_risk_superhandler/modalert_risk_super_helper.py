# encoding = utf-8

def process_event(helper, *args, **kwargs):
    """
    __author__ = "Guilhem Marchand"
    __email___ = "gmarchand@splunk.com"
    __version__ = "0.1.0"
    __status__ = "PRODUCTION"

    Note: There are some differences between the custom command code and the mod alert handler, especially mv fields
    are provided differently from the alert action (structure __mv_<field name>) and require the usage a CIM module, while
    in the context of the custom command fields are transparently handled as lists if in a mv format
    """

    helper.log_info("Alert action risk_super started.")

    import splunk
    import splunk.entity
    import json
    import csv
    import time
    import tempfile
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

    # import cim_modactions
    modaction_path = os.path.join(splunkhome, "etc", "apps", "Splunk_SA_CIM", "lib", "cim_actions.py")
    import cim_actions

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

    #################################################################
    # Loop through the records and proceed
    # The custom command does not alter the original search results #    
    #################################################################

    for record in records:

        # log debug
        helper.log_debug("record=\"{}\"".format(json.dumps(record)))

        # Write to a tempfile
        # Get tempdir
        tempdir = os.path.join(splunkhome, 'etc', 'apps', 'TA-risk-superhandler', 'tmp')
        if not os.path.isdir(tempdir):
            os.mkdir(tempdir)

        # Set the temp file
        results_json = tempfile.NamedTemporaryFile(mode='w+t', prefix="splunk_alert_results_" + str(time.time()) + "_", suffix='.json', dir=tempdir, delete=False)      

        # Write our json record
        results_json.writelines(json.dumps(record))
        results_json.seek(0)

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
                return 1

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

                splQueryRoot = "| riskjsonload json_path=\"" + results_json.name + "\" | spath | rename \"*{}\" as \"*\""
                helper.log_debug("splQueryRoot=\"{}\"".format(splQueryRoot))
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

                # Store type of object in a list
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
                        helper.log_debug("No risk object in jsonSubObj=\"{}\"".format(jsonSubObj))
                        json_risk_object = None

                    try:

                        # Handle threat_object_field
                        threat_object_field = jsonSubObj['threat_object_field']
                        helper.log_debug("threat_object_field=\"{}\"".format(threat_object_field))

                        # check if this is a list itself

                        # check an mv field exist for this
                        threat_object_mv_field = []
                        try:
                            threat_object_mv_field = cim_actions.parse_mv(record["__mv_" + str(threat_object_field)])                       
                            helper.log_debug("threat_object is an mv field, threat_object_mv_field=\"{}\"".format(threat_object_mv_field))

                        except Exception as e:
                            helper.log_debug("threat_object_field was not found in a mv format, exception=\"{}\"".format(e))

                        # Handle all options
                        if len(threat_object_mv_field)>0:
                            for sub_threat_object in threat_object_mv_field:
                                threat_objects_list.append(sub_threat_object)                            
                            
                        elif type(record[threat_object_field]) == list:
                            for sub_threat_object in record[threat_object_field]:
                                threat_objects_list.append(sub_threat_object)

                        else:
                            threat_objects_list.append(record[threat_object_field])
                        helper.log_debug("threat_objects_list=\"{}\"".format(threat_objects_list))

                        # Handle threat_object_type
                        threat_object_type = jsonSubObj['threat_object_type']
                        helper.log_debug("threat_object_type=\"{}\"".format(threat_object_type))
                        threat_objects_type_list.append(threat_object_type)
                        helper.log_debug("threat_objects_type_list=\"{}\"".format(threat_objects_type_list))

                        # Boolean
                        json_threat_object = True

                    except Exception as e:
                        helper.log_debug("No threat object in jsonSubObj=\"{}\"".format(jsonSubObj))
                        json_threat_object = None

                    # Add
                    if json_risk_object:
                        jsonEmptyDict.append({'risk_object_field': risk_object, 'risk_object_type': risk_object_type, 'risk_score': risk_score, 'risk_message': risk_message})
                    elif json_threat_object:
                        jsonEmptyDict.append({'threat_object_field': threat_object_field, 'threat_object_type': threat_object_type})

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

                        # The risk_object value can be provided in 3 options:
                        # - as a single value
                        # - in a mv structured (__mv_risk_object)
                        # - in a native list
                        # - in a pseudo mv structured to be expanded, via a string delimiter

                        # check an mv field exist for this
                        risk_object_mv_field = []
                        try:
                            risk_object_mv_field = cim_actions.parse_mv(record["__mv_" + str(risk_object)])                       
                            helper.log_debug("risk_object is an mv field, risk_object_mv_field=\"{}\"".format(risk_object_mv_field))

                        except Exception as e:
                            helper.log_debug("risk_object was not found in a mv format, exception=\"{}\"".format(e))

                        # handle the format field
                        if not format_separator and len(risk_object_mv_field) == 0 and type(record[risk_object]) != list:

                            # log
                            helper.log_debug("the risk object format is a single value field, risk_object=\"{}\"".format(risk_object))

                            # Set the initial query
                            if spl_count>1:
                                splQuery = str(splQuery) + "\n" +\
                                    "| append [ \n" + str(splQueryRoot) + "\n" +\
                                    "| eval risk_object=\"" + record[risk_object] + "\", risk_object_type=\"" + str(risk_object_type)+ "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                    "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken ]\n"
                            else:
                                splQuery = str(splQueryRoot) + "\n" +\
                                    "| eval risk_object=\"" + record[risk_object] + "\", risk_object_type=\"" + str(risk_object_type) + "\", risk_score=\"" + str(risk_score) + "\"\n" +\
                                    "| eval risk_message=\"" + str(risk_message) + "\" | expandtoken\n"
                            spl_count+=1

                            # If running in pre threat compatible mode, force include the threat_object and threat_object_type fields
                            if len(threat_objects_list) and len(threat_objects_type_list):
                                threat_objects_str = "|".join(threat_objects_list)
                                threat_objects_type_str = "|".join(threat_objects_type_list)
                                splQuery = splQuery + "\n" +\
                                    "| eval threat_object=\"" + threat_objects_str.replace('"', '\\\"') +\
                                    "\", threat_object_type=\"" + threat_objects_type_str + "\" | makemv delim=\"|\" threat_object | makemv delim=\"|\" threat_object_type"

                        else:

                            helper.log_debug("the risk object format is a multivalue format")
                            
                            # if from an __mv_risk_object field
                            if len(risk_object_mv_field) > 0:
                                risk_object_list = risk_object_mv_field

                            # or via the seperator in single value string separated
                            elif format_separator:                            
                                risk_object_list = record[risk_object].split(format_separator)

                            # stored in a native list
                            else:
                                risk_object_list = record[risk_object]

                            for risk_subobject in risk_object_list:
                                helper.log_debug("run the risk action against risk_subobject=\"{}\"".format(risk_subobject))

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

                    # Terminate the search
                    splQuery = str(splQuery) + "\n" +\
                        "| eval search_name=\"" + str(search_name) + "\"\n" +\
                        "| eval _key=search_name | lookup local=true correlationsearches_lookup _key OUTPUTNEW annotations, description as savedsearch_description | spathannotations" +\
                        "| collectrisk search_name=\"" + str(search_name) + "\""

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

        # close and delete transparently
        finally:
            results_json.close()

    return 0
