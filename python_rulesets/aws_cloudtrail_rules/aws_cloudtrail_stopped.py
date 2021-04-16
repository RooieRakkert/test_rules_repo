from python_rules import Rule, deep_get
from _mapping import original_get

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    "DeleteTrail",
    "StopLogging",
}


class CloudTrailStopped(Rule):
    # src: https://bit.ly/3a3u8pg
    id = "dbe80abd-75b8-4e47-ac96-1e4d8386a17e"
    title = "AWS CloudTrail stopped"
    description = "AWS CloudTrail stopped logging."
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        req_params = deep_get(event, 'requestParameters')
        name = req_params.get('name', default="<UNKNOWN_NAME")
        self.description = f"CloudTrail [{name}] in account was stopped/deleted"

        event_name = deep_get(event, 'eventName')

        return event_name in CLOUDTRAIL_STOP_DELETE
