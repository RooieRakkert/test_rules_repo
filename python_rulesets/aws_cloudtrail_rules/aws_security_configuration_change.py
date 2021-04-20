from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

SECURITY_CONFIG_ACTIONS = {
    "DeleteAccountPublicAccessBlock",
    "DeleteDeliveryChannel",
    "DeleteDetector",
    "DeleteFlowLogs",
    "DeleteRule",
    "DeleteTrail",
    "DisableEbsEncryptionByDefault",
    "DisableRule",
    "StopConfigurationRecorder",
    "StopLogging",
}


class AWSSecurityConfigChange(Rule):
    # src: https://bit.ly/3sbhBGk
    id = "9538101d-5e35-4aa2-a612-22e6b1cb1207"
    title = "AWS Security Configuration Changed"
    description = "AWS security config changed"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        if event.get("eventName") == "UpdateDetector":
            return not deep_get(event, "requestParameters", "enable", default=True)

        user = deep_get(event, "userIdentity", "userName") or deep_get(
            event, "userIdentity", "sessionContext", "sessionIssuer", "userName", default="<UNKNOWN_USER>"
        )
        self.description = f"Sensitive AWS API call {event.get('eventName')} made by {user}"

        return event.get("eventName") in SECURITY_CONFIG_ACTIONS
