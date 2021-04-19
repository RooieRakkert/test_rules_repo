from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    "CreateTrail",
    "UpdateTrail",
    "StartLogging",
}


class CloudTrailChanges(Rule):
    # src: https://bit.ly/3fXLXtw
    id = "c0cd9021-5aab-4903-80a4-7d2de697aa28"
    title = "CloudTrail changes detected"
    description = "API calls that are indicative of CloudTrail changes within event!"
    author = "Bouke Hendriks"
    date = "2021/04/08
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        req_params = deep_get(event, 'requestParameters')
        self.description = f"CloudTrail [{req_params.get('name', default='<UNKNOWN_NAME>')}] was created/updated"
        event_name = deep_get(event, 'eventName')

        return event_name in CLOUDTRAIL_CREATE_UPDATE
