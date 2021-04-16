# Flattened

All event keys with `.flattened.` in their name, have to be read through `rapidjson.loads(key)`
This is because we pass our messages down to ES further down the line..


# Additional todo's
- Add severity
- Add MITRE mapping tags