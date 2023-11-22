[<unique_transform_stanza_name>]

@placement search-head, indexer
REGEX = <regular expression>
FORMAT = <string>
MATCH_LIMIT = <integer>
DEPTH_LIMIT = <integer>

@placement search-head, indexer
CLONE_SOURCETYPE = <string>
LOOKAHEAD = <integer>
WRITE_META = [true|false]
DEST_KEY = <KEY>
DEFAULT_VALUE = <string>

@placement search-head, indexer
SOURCE_KEY = <string>

@placement search-head, indexer
REPEAT_MATCH = [true|false]
INGEST_EVAL = <comma-separated list of evaluator expressions>

@placement search-head
DELIMS = <quoted string list>
FIELDS = <quoted string list>
MV_ADD = [true|false]
CLEAN_KEYS = [true|false]
KEEP_EMPTY_VALS = [true|false]
CAN_OPTIMIZE = [true|false]
filename = <string>
collection = <string>
max_matches = <integer>
min_matches = <integer>
default_match = <string>
case_sensitive_match = <bool>
reverse_lookup_honor_case_sensitive_match = <boolean>
match_type = <string>
external_cmd = <string>
fields_list = <string>
index_fields_list = <string>
external_type = [python|executable|kvstore|geo]
python.version = {default|python|python2|python3}
time_field = <string>
time_format = <string>
max_offset_secs = <integer>
min_offset_secs = <integer>
batch_index_query = <bool>
allow_caching = <bool>
cache_size = <integer>
max_ext_batch = <integer>
filter = <string>
feature_id_element = <string>
check_permission = <boolean>
replicate = <boolean>

@placement search-head, indexer
<name> = <key>

@placement search-head, indexer
REMOVE_DIMS_FROM_METRIC_NAME = <boolean>
METRIC-SCHEMA-MEASURES-<unique_metric_name_prefix> = (_ALLNUMS_ | (_NUMS_EXCEPT_ )? <field1>, <field2>,... )
METRIC-SCHEMA-BLACKLIST-DIMS-<unique_metric_name_prefix> = <dimension_field1>,<dimension_field2>,...
METRIC-SCHEMA-WHITELIST-DIMS-<unique_metric_name_prefix> = <dimension_field1>,<dimension_field2>,...
METRIC-SCHEMA-MEASURES = (_ALLNUMS_ | (_NUMS_EXCEPT_ )? <field1>, <field2>,... )
METRIC-SCHEMA-BLACKLIST-DIMS = <dimension_field1>, <dimension_field2>,...
METRIC-SCHEMA-WHITELIST-DIMS = <dimension_field1>, <dimension_field2>,...
