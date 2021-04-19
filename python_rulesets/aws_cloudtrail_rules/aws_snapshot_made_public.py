from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get
from collections.abc import Mapping


class AWSSnapshotMadePublic(Rule):
    # src: https://bit.ly/3g8IAjj
    id = "a6f81df3-a351-4ebf-bbe8-f86e65b2a2b1"
    title = "AWS Snapshot Made Public"
    description = "AWS EC2 or RDS snapshot made publicly accessible"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        # EC2 Volume snapshot made public
        if event.get("eventName") == "ModifySnapshotAttribute":
            parameters = event.get("requestParameters", {})
            if parameters.get("attributeType") != "CREATE_VOLUME_PERMISSION":
                return False

            items = deep_get(parameters, "createVolumePermission", "add", "items", default=[])
            for item in items:
                if not isinstance(item, (Mapping, dict)):
                    continue
                if item.get("group") == "all":
                    return True
            return False

        # RDS snapshot made public
        if event.get("eventName") == "ModifyDBClusterSnapshotAttribute":
            return "all" in deep_get(event, "requestParameters", "valuesToAdd", default=[])

        return False
