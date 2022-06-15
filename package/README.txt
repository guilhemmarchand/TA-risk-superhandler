# Risk Super Handler for Enterprise Security

## Lookup example

- Create a lookup, shared either at the app level of global level, the format of the lookup should adopt the following structure:

```
code_id,json_dict
uc_ref_001,[{"risk_object": "src", "risk_object_type": "system", "risk_score": 100, "risk_message": "Too many auth failures from user=$user$", "format_separator": "|"}, {"risk_object": "user", "risk_object_type": "user", "risk_score": 100, "risk_message": "Too many auth failures from user=$user$"}]
```

## Calling the action

