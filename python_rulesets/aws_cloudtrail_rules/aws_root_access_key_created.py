from python_rules import Rule
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class AWSRootAccessKeyCreation(Rule):
    # src: https://bit.ly/3wR241P
    id = "37a710ad-20a1-49a1-8f9a-9517d840fa7b"
    title = "AWS Root Access Key Creation"
    description = "Creation of AWS key with root access"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "high"

    def rule(self, e):
        event = original_get(e)
        if event.get("eventName") != "CreateAccessKey":
            return False

            # Only root can create root access keys
        if deep_get(event, "userIdentity", "type") != "Root":
            return False

            # Only alert if the root user is creating an access key for itself
        return event.get("requestParameters") is None
