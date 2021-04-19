from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_CREATE_EVENTS = {
    "PutDeliveryChannel",
    "PutConfigurationRecorder",
    "StartConfigurationRecorder",
}


class ConfigServiceCreated(Rule):
    # src: https://bit.ly/2QiQUSY
    id = "8533b1a6-8192-4082-a97b-edb5d520db95"
    title = "AWS config service created"
    description = "AWS configuration service created"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return deep_get(event, 'eventName') in CONFIG_SERVICE_CREATE_EVENTS
