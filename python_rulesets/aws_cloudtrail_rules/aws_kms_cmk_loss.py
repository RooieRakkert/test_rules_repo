from python_rules import Rule
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of KMS CMK Deletion
KMS_LOSS_EVENTS = {"DisableKey", "ScheduleKeyDeletion"}
KMS_KEY_TYPE = "AWS::KMS::Key"


class KMSCMKLoss(Rule):
    # src: https://bit.ly/3vb4PcZ
    id = "1f930bb7-33a7-4e68-b4c4-fee736d77bd7"
    title = "AWS KMS CMK Loss"
    description = "AWS KMS CMK Deletion"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return event.get("eventName") in KMS_LOSS_EVENTS