from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class AMIModifiedPublicAccess(Rule):
    # src: https://bit.ly/3wLl7e1
    id = "b99ddd0d-fa3c-4631-995e-9625a10afc7d"
    title = "AWS AMI modified for public access"
    description = "AWS AMI modified for public access"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        # Only check ModiyImageAttribute events
        if deep_get(event, 'eventName') != "ModifyImageAttribute":
            return False

        params = deep_get(event, 'requestParameters')
        added_perms = deep_get(params, "launchPermission", "add", "items", default=[])

        for item in added_perms:
            if item.get("group") == "all":
                return True

        return False
