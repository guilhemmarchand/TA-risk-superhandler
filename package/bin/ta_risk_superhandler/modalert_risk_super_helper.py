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

    import json
    import csv
    import time
    import tempfile
    import re
    import os, sys
    import splunklib.client as client
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    splunkhome = os.environ["SPLUNK_HOME"]

    sys.path.append(
        os.path.join(splunkhome, "etc", "apps", "TA-risk-superhandler", "lib")
    )

    # import Splunk libs
    import splunklib.client as client
    import splunklib.results as results

    # import cim_modactions
    modaction_path = os.path.join(
        splunkhome, "etc", "apps", "Splunk_SA_CIM", "lib", "cim_actions.py"
    )
    import cim_actions

    # import additional libs
    from libs_risksuperhandler import get_full_kv_collection, handler_dedup_risk

    # Retrieve the session_key
    helper.log_debug("Get session_key.")
    session_key = helper.session_key

    # Get splunkd port
    try:
        splunkd_port_search = re.search(
            "'server_uri':\s'(?:http|https)://[^\:]+\:(\d+)'",
            str(vars(helper)),
            re.IGNORECASE,
        )
        if splunkd_port_search:
            splunkd_port = splunkd_port_search.group(1)
            helper.log_debug(
                'splunkd_port="{}" extracted successfully'.format(splunkd_port)
            )
    except Exception as e:
        helper.log_error(
            'Failed to extract splunkd_port from server_uri with exception="{}"'.format(
                e
            )
        )
        splunkd_port = "8089"

    # get service
    service = client.connect(
        owner="nobody", app="TA-risk-superhandler", port=splunkd_port, token=session_key
    )

    # Get our alert config
    uc_lookup_path = helper.get_param("uc_lookup_path")
    helper.log_info("uc_lookup_path={}".format(uc_lookup_path))

    uc_ref_field = helper.get_param("uc_ref_field")
    helper.log_info("uc_ref_field={}".format(uc_ref_field))

    dedup = helper.get_param("dedup")
    try:  # Convert to boolean
        dedup = bool(dedup)
    except Exception as e:
        dedup = True
    helper.log_info("dedup={}".format(dedup))

    min_sec_since_last_riskevent = helper.get_param("min_sec_since_last_riskevent")
    try:
        min_sec_since_last_riskevent = int(min_sec_since_last_riskevent)
    except Exception as e:
        min_sec_since_last_riskevent = 900
    helper.log_info(
        "min_sec_since_last_riskevent={}".format(min_sec_since_last_riskevent)
    )

    #
    # Dedup KVstore collection
    #

    collection_name = "kv_risk_superhandler_dedup"
    collection = service.kvstore[collection_name]

    # if dedup is enabled, retrieve the full content of the KVstore collection
    if dedup:
        collection_records, collection_records_keys, collection_dict = (
            get_full_kv_collection(collection, collection_name)
        )
        helper.log_debug(f'collection_dict="{json.dumps(collection_dict, indent=2)}"')

    # Check the CSV lookup file
    csv_dict_file = os.path.join(splunkhome, "etc", "apps", uc_lookup_path)
    helper.log_debug('uc_lookup_path="{}"'.format(uc_lookup_path))
    helper.log_debug(
        'Attempting to read the csv_dict from file="{}"'.format(csv_dict_file)
    )

    # Check if the lookup file exists
    if not os.path.isfile(csv_dict_file):
        helper.log_error(
            'The uc_lookup_path="{}" was provided as part of the arguments, but this file does not exist or is not readable'.format(
                csv_dict_file
            )
        )
        return 1

    # conf
    conf_file = "ta_risk_superhandler_settings"
    confs = service.confs[str(conf_file)]

    # Advanced configuration
    # retrive the list of risk_object block list patterns (optional)
    try:
        blocklist_risk_object_patterns_tmp = []
        blocklist_risk_object_patterns = []

        for stanza in confs:
            if stanza.name == "advanced_configuration":
                for key, value in stanza.content.items():
                    if key == "blocklist_risk_object_patterns" and value:
                        blocklist_risk_object_patterns_tmp = re.split(r',(?=")', value)

        # handle double quotes
        for blocklist_pattern in blocklist_risk_object_patterns_tmp:
            result = re.match(r"\"([^\"]*)\"", blocklist_pattern)
            if result:
                blocklist_risk_object_patterns.append(result.group(1))
        helper.log_debug(
            'blocklist, a list for risk_object forbidden value was provided blocklist_risk_object_patterns="{}"'.format(
                blocklist_risk_object_patterns
            )
        )
    except Exception as e:
        helper.log_error(
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
        helper.log_debug(
            'blocklist, a list for threat_object forbidden value was provided blocklist_threat_object_patterns="{}"'.format(
                blocklist_threat_object_patterns
            )
        )
    except Exception as e:
        helper.log_error(
            'failed to retrieve threat_object blocklist with exception="{}"'.format(
                str(e)
            )
        )
        blocklist_threat_object_patterns = []

    # Loop through the results
    records = helper.get_events()

    #################################################################
    # Loop through the records and proceed
    # The custom command does not alter the original search results #
    #################################################################

    # boolean used to define if the final action should be executed
    run_riskcollect = False

    # boolean used to define if we shall start the risk process
    start_riskprocess = False

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

        # Our new record dict
        new_record = {}

        # log debug
        helper.log_debug('record="{}"'.format(json.dumps(record)))

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
                uc_ref = record[uc_ref_field]
                helper.log_debug('uc_ref="{}"'.format(uc_ref))
                start_riskprocess = True
            except Exception as e:
                helper.log_error(
                    'failed to retrieve the uc_ref using requested field="{}" from the upstream results'.format(
                        uc_ref_field, json.dumps(record)
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

                if uc_lookup_path:

                    # Open the csv lookup
                    csv_file = open(csv_dict_file, "r")
                    readCSV = csv.DictReader(
                        csv_file, delimiter=str(","), quotechar=str('"')
                    )

                    # log
                    helper.log_debug('csv_data="{}"'.format(readCSV))

                    # Loop
                    for row in readCSV:

                        # log
                        helper.log_debug('In lookup row="{}"'.format(row))
                        helper.log_debug(
                            'In lookup looking for match with ref="{}"'.format(
                                record[uc_ref_field]
                            )
                        )
                        helper.log_debug(
                            'In lookup content uc_ref_field="{}"'.format(
                                row[uc_ref_field]
                            )
                        )
                        helper.log_debug(
                            'In lookup content json_dict="{}"'.format(row["json_dict"])
                        )
                        helper.log_debug(
                            "if {} is equal to {}".format(
                                row[uc_ref_field], record[uc_ref_field]
                            )
                        )

                        if row[uc_ref_field] == record[uc_ref_field]:
                            helper.log_info(
                                'uc_ref="{}", use case lookup record found, row="{}"'.format(
                                    record[uc_ref_field], json.dumps(row)
                                )
                            )
                            jsonDict = row["json_dict"]
                            run_riskcollect = True
                            break

                # process if we have a JSON rule object
                if not jsonDict:
                    helper.log_info(
                        'No lookup record match for use case uc_ref="{}", risk event creation will not be actioned'.format(
                            record[uc_ref_field]
                        )
                    )
                    run_riskcollect = False

                else:
                    # Attempt to load the json dict as a Python object
                    try:
                        jsonObj = json.loads(jsonDict)
                        helper.log_info(
                            'record match for use case uc_ref="{}", risk_rules were loaded successfully, jsonObj="{}"'.format(
                                record[uc_ref_field], json.dumps(jsonObj)
                            )
                        )
                    except Exception as e:
                        helper.log_error(
                            'Failure to load the json object, use case uc_ref="{}", exception="{}"'.format(
                                record[uc_ref_field], e
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
                            helper.log_debug(
                                "No search_name was provided in the JSON object"
                            )

                    # Hande the threat, will be added to the JSON object submitted in the risk param

                    # Store type of object in a list
                    threat_objects_list = []
                    threat_objects_type_list = []

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
                            helper.log_debug(
                                'No risk object in jsonSubObj="{}"'.format(jsonSubObj)
                            )
                            json_risk_object = None

                        try:

                            # Handle threat_object_field
                            threat_object_field = jsonSubObj["threat_object_field"]
                            helper.log_debug(
                                'threat_object_field="{}"'.format(threat_object_field)
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
                                helper.log_debug(
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
                                helper.log_debug(
                                    'threat_object is an mv field, threat_object_mv_field="{}"'.format(
                                        threat_object_mv_field
                                    )
                                )

                            except Exception as e:
                                helper.log_debug(
                                    'threat_object_field was not found in a mv format, exception="{}"'.format(
                                        e
                                    )
                                )

                            # Handle all options

                            # check if it is a standard single value field
                            if (
                                not format_separator_threat_object
                                and len(threat_object_mv_field) == 0
                                and type(record[threat_object_field]) != list
                            ):

                                # log
                                helper.log_debug(
                                    'the threat_object format is a single value field, threat_object="{}"'.format(
                                        record[threat_object_field]
                                    )
                                )

                                # check blocklist
                                if (
                                    record[threat_object_field]
                                    in blocklist_threat_object_patterns
                                ):
                                    helper.log_warn(
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

                                helper.log_debug(
                                    "the threat_object format is a multivalue format"
                                )

                                # check if it is an mvfield
                                if len(threat_object_mv_field) > 0:
                                    for sub_threat_object in threat_object_mv_field:
                                        threat_objects_list.append(sub_threat_object)

                                # check if it is a native list
                                elif type(record[threat_object_field]) == list:
                                    for sub_threat_object in record[
                                        threat_object_field
                                    ]:
                                        threat_objects_list.append(sub_threat_object)

                                # check if a custom format delimiter is set set
                                elif format_separator_threat_object:

                                    try:
                                        threat_objects_list = record[
                                            threat_object_field
                                        ].split(format_separator_threat_object)
                                        helper.log_debug(
                                            'uc_ref="{}", successfully loaded the threat_object field as a custom separated format using format_separator="{}"'.format(
                                                record[uc_ref_field],
                                                format_separator_threat_object,
                                            )
                                        )
                                    except Exception as e:
                                        threat_objects_list = record[
                                            threat_object_field
                                        ]
                                        helper.log_debug(
                                            'uc_ref="{}", could not load the field="{}" as a format separated field, the rule definition is likely incorrect, exception="{}"'.format(
                                                record[uc_ref_field],
                                                threat_object_field,
                                                str(e),
                                            )
                                        )

                            # Add to the record
                            new_record["threat_object"] = threat_objects_list

                            # check blocklist (remove from list if blocklisted)
                            for threat_object in threat_objects_list:
                                if threat_object in blocklist_threat_object_patterns:
                                    helper.log_warn(
                                        'blocklist: the threat_object="{}" is not allowed as per blocklist_threat_object_patterns="{}"'.format(
                                            threat_object,
                                            blocklist_threat_object_patterns,
                                        )
                                    )
                                    threat_objects_list.remove(threat_object)

                            # Handle threat_object_type
                            threat_object_type = jsonSubObj["threat_object_type"]
                            helper.log_debug(
                                'threat_object_type="{}"'.format(threat_object_type)
                            )
                            threat_objects_type_list.append(threat_object_type)
                            helper.log_debug(
                                'threat_objects_type_list="{}"'.format(
                                    threat_objects_type_list
                                )
                            )

                            # Add
                            new_record["threat_object_type"] = threat_objects_type_list

                            # Boolean
                            json_threat_object = True

                        except Exception as e:
                            helper.log_debug(
                                'No threat object in jsonSubObj="{}"'.format(jsonSubObj)
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
                    helper.log_debug(
                        'jsonEmptyDict="{}"'.format(json.dumps(jsonEmptyDict))
                    )

                    # override if any
                    if json_search_name:
                        search_name = json_search_name
                        helper.log_debug(
                            'search_name was overriden via the JSON dictionnary, search_name="{}"'.format(
                                search_name
                            )
                        )

                    # Lookup through the dict again and proceed
                    for jsonSubObj in jsonObj:
                        helper.log_debug(
                            'jsonSubObj="{}"'.format(json.dumps(jsonSubObj, indent=1))
                        )

                        # Handle if the JSON object contains a risk rule
                        jsonSubObjHasRisk = None

                        try:
                            risk_object = jsonSubObj["risk_object"]
                            jsonSubObjHasRisk = True
                        except Exception as e:
                            jsonSubObjHasRisk = None
                            helper.log_debug(
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
                                    helper.log_info(
                                        "A value for risk_score of {} was found in the event, this will override the JSON definition".format(
                                            event_risk_score
                                        )
                                    )
                                    risk_score = event_risk_score

                            except Exception as e:
                                helper.log_debug(
                                    "There are no risk_score value defined at the event level"
                                )

                            # Verify that the risk_object field exists, and proceed
                            risk_object_value = None
                            try:
                                risk_object_value = record[risk_object]
                            except Exception as e:
                                helper.log_error(
                                    'uc_ref="{}", cannot extract the risk_object="{}", the field does not exist and will be ignored, record="{}"'.format(
                                        record[uc_ref_field],
                                        risk_object,
                                        json.dumps(record),
                                    )
                                )

                            if (
                                risk_object_value
                                and not risk_object_value
                                in blocklist_risk_object_patterns
                            ):

                                # Allow a field to be provided as part of an mv structure by submitting a delimiter, if no delimiter assume the field is a regular
                                # single value
                                try:
                                    format_separator = jsonSubObj["format_separator"]
                                except Exception as e:
                                    format_separator = None

                                # log
                                helper.log_info(
                                    'risk rule loaded, uc_ref="{}", risk_object="{}", risk_object_type="{}", risk_score="{}", risk_message="{}", format_field="{}"'.format(
                                        record[uc_ref_field],
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
                                    helper.log_debug(
                                        'risk_object is an mv field, risk_object_mv_field="{}"'.format(
                                            risk_object_mv_field
                                        )
                                    )

                                except Exception as e:
                                    helper.log_debug(
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
                                        helper.log_warn(
                                            'blocklist: the risk_object="{}" is not allowed as per blocklist_risk_object_patterns="{}"'.format(
                                                record[risk_object],
                                                blocklist_risk_object_patterns,
                                            )
                                        )

                                    else:

                                        # log
                                        helper.log_debug(
                                            'the risk object format is a single value field, risk_object="{}"'.format(
                                                risk_object
                                            )
                                        )

                                        # Handle this mv structure in a new record
                                        mv_record = {}
                                        for k in new_record:
                                            mv_record[k] = new_record[k]
                                        helper.log_debug(
                                            'mv_record="{}"'.format(mv_record)
                                        )

                                        # Add
                                        mv_record["risk_object"] = record[risk_object]
                                        mv_record["risk_object_type"] = risk_object_type
                                        mv_record["risk_score"] = risk_score
                                        mv_record["risk_message"] = risk_message

                                        # Add original fields
                                        for k in record:
                                            if not k.startswith("__mv"):
                                                mv_record[k] = record[k]

                                        #
                                        # Dedup
                                        #

                                        # add_risk_record boolean, True by default
                                        add_risk_record = True

                                        # check if mv_record_key_factors is in the dedup collection
                                        if dedup:
                                            try:
                                                add_risk_record = handler_dedup_risk(
                                                    min_sec_since_last_riskevent,
                                                    record[uc_ref_field],
                                                    mv_record,
                                                    collection_dict,
                                                    collection,
                                                )
                                            except Exception as e:
                                                helper.log_error(
                                                    'function handler_dedup_risk, failed to handle dedup risk with exception="{}"'.format(
                                                        e
                                                    )
                                                )
                                                add_risk_record = True

                                        # Add to final records
                                        if add_risk_record:
                                            all_new_records.append(mv_record)

                                else:

                                    helper.log_debug(
                                        "the risk object format is a multivalue format"
                                    )

                                    # if from an __mv_risk_object field
                                    if len(risk_object_mv_field) > 0:
                                        risk_object_list = risk_object_mv_field

                                    # or via the seperator in single value string separated
                                    elif (
                                        format_separator
                                        and type(record[risk_object]) != list
                                    ):
                                        try:
                                            risk_object_list = record[
                                                risk_object
                                            ].split(format_separator)
                                        except Exception as e:
                                            risk_object_list = record[risk_object]
                                            helper.log_warn(
                                                'uc_ref="{}", could not load the field="{}" as a format separated field, the rule definition is likely incorrect, exception="{}"'.format(
                                                    record[uc_ref_field],
                                                    risk_object,
                                                    str(e),
                                                )
                                            )

                                    # stored in a native list
                                    else:

                                        # if the format separator was incorrectly set, generate a warning message
                                        if format_separator:
                                            helper.log_warn(
                                                'uc_ref="{}", the risk_object="{}" has a format_separator="{}" but it comes as a multivalue field instead, this configuration is likely incorrect'.format(
                                                    record[uc_ref_field],
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
                                            helper.log_warn(
                                                'blocklist: the risk_object="{}" is not allowed as per blocklist_risk_object_patterns="{}"'.format(
                                                    risk_subobject,
                                                    blocklist_risk_object_patterns,
                                                )
                                            )

                                        else:
                                            if risk_subobject:
                                                helper.log_debug(
                                                    'run the risk action against risk_subobject="{}"'.format(
                                                        risk_subobject
                                                    )
                                                )

                                                # Handle this mv structure in a new record
                                                mv_record = {}
                                                for k in new_record:
                                                    mv_record[k] = new_record[k]
                                                helper.log_debug(
                                                    'mv_record="{}"'.format(mv_record)
                                                )

                                                # Add
                                                mv_record["risk_object"] = (
                                                    risk_subobject
                                                )
                                                mv_record["risk_object_type"] = (
                                                    risk_object_type
                                                )
                                                mv_record["risk_score"] = risk_score
                                                mv_record["risk_message"] = risk_message

                                                # Add original fields
                                                for k in record:
                                                    if not k.startswith("__mv"):
                                                        mv_record[k] = record[k]

                                                #
                                                # Dedup
                                                #

                                                # add_risk_record boolean, True by default
                                                add_risk_record = True

                                                # check if mv_record_key_factors is in the dedup collection
                                                if dedup:
                                                    try:
                                                        add_risk_record = handler_dedup_risk(
                                                            min_sec_since_last_riskevent,
                                                            record[uc_ref_field],
                                                            mv_record,
                                                            collection_dict,
                                                            collection,
                                                        )
                                                    except Exception as e:
                                                        helper.log_error(
                                                            'function handler_dedup_risk, failed to handle dedup risk with exception="{}"'.format(
                                                                e
                                                            )
                                                        )
                                                        add_risk_record = True

                                                # Add to final records
                                                if add_risk_record:
                                                    all_new_records.append(mv_record)

        # Initial exception handler
        except Exception as e:
            helper.log_error(
                'An exception was encountered while processing the risk actions, exception="{}"'.format(
                    e
                )
            )

        # Add all fields from the record, except __mv structure
        for k in record:
            if not k.startswith("__mv"):
                new_record[k] = record[k]

    # Additional safety: if none of the expected fields in the Risk definition could be found (the JSON definition is incorrect or the event unexpected)
    # Don't run the rest of the logic

    if not all_new_records:
        helper.log_debug(
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

        helper.log_debug('splQuery="{}"'.format(splQuery))

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
            helper.log_info(
                'risk command was successful, result="{}"'.format(
                    json.dumps(query_result, indent=0)
                )
            )

        except Exception as e:
            helper.log_error('risk command has failed with exception="{}"'.format(e))

        finally:

            # close the json
            results_json.close()

            # delete
            if os.path.isfile(results_json.name):
                try:
                    os.remove(results_json.name)
                except Exception as e:
                    helper.log_error(
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
                helper.log_error(
                    'Failure to remove temporary file, path="{}", exception="{}"'.format(
                        results_json.name, e
                    )
                )

    return 0
