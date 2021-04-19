from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of an AWS Config Service change
CONFIG_SERVICE_DISABLE_DELETE_EVENTS = {
    "StopConfigurationRecorder",
    "DeleteDeliveryChannel",
}


class ConfigServiceDeleted(Rule):
    # src: https://bit.ly/3dcOwGq
    id = "2f625eab-4964-49b5-b7d2-fa915f896452"
    title = "AWS config service deleted"
    description = "AWS configuration service deleted"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return deep_get(event, 'eventName') in CONFIG_SERVICE_DISABLE_DELETE_EVENTS
