from python_rules import deep_get
import rapidjson


def original_get(e, key='event.original', default=None):
    # used to return event.original field, deserialized into dictionary
    # if key not found, we return empty dict
    nested = deep_get(e, *key.split('.'))
    if nested is None:
        return default
    try:
        # deserialize, for example a field with '.flattened.' or 'event.original'
        return rapidjson.loads(nested)
    except:  # couldn't be deseralized
        return nested