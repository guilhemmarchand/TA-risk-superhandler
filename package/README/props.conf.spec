[<spec>]
priority = <number>

@placement search-head, indexer
CHARSET = <string>
TRUNCATE = <non-negative integer>
LINE_BREAKER = <regular expression>
LINE_BREAKER_LOOKBEHIND = <integer>
SHOULD_LINEMERGE = [true|false]
BREAK_ONLY_BEFORE_DATE = [true|false]
BREAK_ONLY_BEFORE = <regular expression>
MUST_BREAK_AFTER = <regular expression>
MUST_NOT_BREAK_AFTER = <regular expression>
MUST_NOT_BREAK_BEFORE = <regular expression>
MAX_EVENTS = <integer>
INDEXED_EXTRACTIONS = < CSV|W3C|TSV|PSV|JSON >
METRIC-SCHEMA-TRANSFORMS = <metric-schema:stanza_name>[,<metric-schema:stanza_name>]...

@placement search-head, indexer
DATETIME_CONFIG = <filename relative to $SPLUNK_HOME>
TIME_PREFIX = <regular expression>
MAX_TIMESTAMP_LOOKAHEAD = <integer>
TIME_FORMAT = <strptime-style format>
DETERMINE_TIMESTAMP_DATE_WITH_SYSTEM_TIME = <boolean>
TZ = <timezone identifier>
TZ_ALIAS = <key=value>[,<key=value>]...
MAX_DAYS_AGO = <integer>
MAX_DAYS_HENCE = <integer>
MAX_DIFF_SECS_AGO = <integer>
MAX_DIFF_SECS_HENCE = <integer>
ADD_EXTRA_TIME_FIELDS = [none | subseconds | all | <boolean>]

@placement search-head, indexer
TRANSFORMS-<class> = <transform_stanza_name>, <transform_stanza_name2>,...

@placement search-head
REPORT-<class> = <transform_stanza_name>, <transform_stanza_name2>,...
EXTRACT-<class> = [<regex>|<regex> in <src_field>]
KV_MODE = [none|auto|auto_escaped|multi|json|xml]
MATCH_LIMIT = <integer>
DEPTH_LIMIT = <integer>
AUTO_KV_JSON = [true|false]
KV_TRIM_SPACES = true|false
CHECK_FOR_HEADER = [true|false]

@placement search-head, indexer
SEDCMD-<class> = <sed script>

@placement search-head
FIELDALIAS-<class> = (<orig_field_name> AS <new_field_name>)+
EVAL-<fieldname> = <eval statement>
LOOKUP-<class> = $TRANSFORM (<match_field> (AS <match_field_in_event>)?)+ (OUTPUT|OUTPUTNEW (<output_field> (AS <output_field_in_event>)? )+ )?

@placement search-head, indexer
SEGMENTATION = <segmenter>

@placement search-head
SEGMENTATION-<segment selection> = <segmenter>

@placement search-head
rename = <string>

@placement search-head, indexer
ANNOTATE_PUNCT = [true|false]

@placement search-head
description = <string>
category = <string>
