Administrative Reference matrix
===============================

Scheduled Alerts and reports
----------------------------

Scheduled alerts reference
^^^^^^^^^^^^^^^^^^^^^^^^^^

DHL MQ messages publishing - relay publishing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is the main modular alert which handles submission to MQ for:**

- Batches of multi-line messages (the field ``multiline`` in the KVstore contains the boolean with value ``1``)
- Re-attempt for submission failures for both single-line and multi-line messages

**SHC versus HF:**

- SHC: This alert does nothing on the SHC, and can be safety disabled
- HF: This alert performs the submission to IBM MQ

DHL MQ messages publishing - batch failing detected
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is an out of the box alert to detect when a batch is failing, either temporary or permanently.**

**SHC versus HF:**

- SHC: This alert is to be running on the search head layer
- HF: This alert will not do anything on the HFs

DHL MQ messages publishing - batch is pending from approval
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is an out of the box alert to detect when a batch was submitted and is pending for approval.**

**SHC versus HF:**

- SHC: This alert is to be running on the search head layer
- HF: This alert will not do anything on the HFs

DHL MQ HA group - registered consumer is offline
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is an out of the box alert to detect when a consumer is offline.**

**SHC versus HF:**

- SHC: This alert is to be running on the search head layer
- HF: This alert will not do anything on the HFs

Scheduled reports reference
^^^^^^^^^^^^^^^^^^^^^^^^^^^

DHL MQ maintenance - purge records from the main MQ backlog KVstore collection
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This scheduled reports purges the old records from the main MQ backlog KVstore collection according to the KVstore eviction and retention policy.**

**SHC versus HF:**

- SHC: This report runs on the search head layer
- HF: This report does nothing on the consumers and can be safety disabled if necessary

DHL MQ messages publishing - batch relay publishing for singleline messages
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This scheduled reports handles the MQ submission for singleline messages sent in mass batches.**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ maintenance - clean any remaining files in massbatch and batch folders
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is a maintenance report which ensures that there are no orphans left by the submission processus on the Heavy Forwarders.**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ maintenance - purge old records from the local cache of the consumers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is a maintenance report which purges old records from the local cache consumers. (by default, records older than 48hours)**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ messages publishing - batch relay flush successfully procedded records
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This is a maintenance report which flushed every 2 minutes the successfully proceeded records for the remote KVstore and the local consumer cache.**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ HA group - send keepalive consumer
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This scheduled report sends a keep alive information to the SHC, and is used for High availability purposes.**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ HA group - get ha groups from remote storage
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This scheduled report retrieves the node manager information from the SHC and puts them in cache in a local KVstore on the consumers, it is used for High availability purposes.**

**SHC versus HF:**

- SHC: This report is designed for Heavy Forwarders, it does nothing on the search head layer and can be safety disabled
- HF: This report runs on the HF

DHL MQ HA group - manager group election
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

**This scheduled reports performs the node manager election per high availability group, and stores the information in a local KVstore of the SHC.**

**SHC versus HF:**

- SHC: This report is designed for to run on the SHC
- HF: On the HF, this report does nothing and can be safety disabled if necessary
