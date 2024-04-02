#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

# Standard library imports
import os
import sys
import time
import logging
import json
import hashlib

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# appebd lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-risk-superhandler", "lib"))


def get_full_kv_collection(collection, collection_name):
    """
    Get all records from a KVstore collection.

    :param collection: The KVstore collection object.
    :param collection_name: The name of the collection to query.

    :return: A tuple containing the records, keys, and a dictionary of the records.

    """
    collection_records = []
    collection_records_keys = set()
    collection_dict = {}

    try:
        end = False
        skip_tracker = 0
        while end == False:
            process_collection_records = collection.data.query(skip=skip_tracker)
            if len(process_collection_records) != 0:
                for item in process_collection_records:
                    if item.get("_key") not in collection_records_keys:
                        collection_records.append(item)
                        collection_records_keys.add(item.get("_key"))
                        collection_dict[item.get("_key")] = item
                skip_tracker += 20000
            else:
                end = True

        return collection_records, collection_records_keys, collection_dict

    except Exception as e:
        logging.error(
            f"failed to call get_kv_collection, args={collection_name}, exception={str(e)}"
        )
        raise Exception(str(e))


def handler_dedup_risk(
    min_sec_since_last_riskevent, uc_ref, risk_record, collection_dict, collection
):
    """
    Deduplication handler for risk events.

    return: add_risk_record (Boolean)

    """

    # set risk_object_type / risk_object
    risk_object_type = risk_record["risk_object_type"]
    risk_object = risk_record["risk_object"]

    # take into account the cim_entity_zone, if any
    risk_cim_entity_zone = risk_record.get("cim_entity_zone", None)

    # define unique factor and its md5
    if risk_cim_entity_zone:
        mv_record_key_factors = (
            f"{uc_ref}:{risk_cim_entity_zone}:{risk_object_type}:{risk_object}"
        )

    else:
        mv_record_key_factors = f"{uc_ref}:{risk_object_type}:{risk_object}"

    # for visualization purposes
    if not risk_cim_entity_zone:
        risk_cim_entity_zone = "N/A"

    # calculate the md5
    mv_record_key_md5 = hashlib.md5(mv_record_key_factors.encode()).hexdigest()

    # check if mv_record_key_factors is in the dedup collection
    if mv_record_key_md5 in collection_dict:

        risk_collection_record = collection_dict[mv_record_key_md5]
        logging.debug(
            f'context="dedup", Found mv_record_key_md5="{mv_record_key_md5}" in the dedup collection'
        )

        # check if the last time is older than min_sec_since_last_riskevent
        last_risk_time = float(risk_collection_record.get("mtime"))
        logging.debug(f'context="dedup", last_risk_time="{last_risk_time}"')
        current_time = int(time.time())
        logging.debug(f'context="dedup", current_time="{current_time}"')
        time_diff = current_time - last_risk_time
        logging.debug(f'context="dedup", time_diff="{time_diff}"')
        if time_diff < min_sec_since_last_riskevent:
            logging.info(
                f'context="dedup", uc_ref="{uc_ref}", mv_record_key_factors="{mv_record_key_factors}" is a duplicate risk event, the last risk event was generated {time_diff} seconds ago, the minimum time is {min_sec_since_last_riskevent} seconds'
            )

            # return
            return False

        else:

            #
            # Accepted risk record
            #

            logging.debug(
                f'context="dedup", uc_ref="{uc_ref}", mv_record_key_factors="{mv_record_key_factors}" is not a duplicate risk event, the last risk event was generated {time_diff} seconds ago, the minimum time is {min_sec_since_last_riskevent} seconds'
            )

            # update the KVstore record
            try:
                collection.data.update(
                    mv_record_key_md5,
                    json.dumps(
                        {
                            "mtime": time.time(),
                            "cim_entity_zone": risk_cim_entity_zone,
                            "risk_uc_ref": uc_ref,
                            "risk_object_type": risk_object_type,
                            "risk_object": risk_object,
                        }
                    ),
                )
            except Exception as e:
                logging.error(
                    f'context="dedup", failed to update the dedup record, exception="{e}"'
                )

            return True

    else:
        #
        # New risk record: first time we see this combination of factors
        #

        logging.debug(
            f'context="dedup", uc_ref="{uc_ref}", mv_record_key_factors="{mv_record_key_factors}" is not in the dedup collection'
        )

        try:
            collection.data.insert(
                json.dumps(
                    {
                        "_key": mv_record_key_md5,
                        "mtime": time.time(),
                        "cim_entity_zone": risk_cim_entity_zone,
                        "risk_uc_ref": uc_ref,
                        "risk_object_type": risk_object_type,
                        "risk_object": risk_object,
                    }
                )
            )
        except Exception as e:
            logging.error(
                f'context="dedup", failed to insert the dedup record, exception="{str(e)}"'
            )

        return True
