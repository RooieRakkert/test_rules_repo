from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

EVENT_ALLOW_LIST = {"CreateServiceLinkedRole", "ConsoleLogin"}


class AWSRootActivity(Rule):
    # src: https://bit.ly/3g6sl6s
    id = "66dbdd96-6e1c-4077-86fa-16baedd5ffe5"
    title = "AWS Root Activity"
    description = "Activity detected on root account"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return (
                deep_get(event, "userIdentity", "type") == "Root"
                and event.get("errorMessage") is None
                and deep_get(event, "userIdentity", "invokedBy") is None
                and event.get("eventType") != "AwsServiceEvent"
                and event.get("eventName") not in EVENT_ALLOW_LIST
        )
