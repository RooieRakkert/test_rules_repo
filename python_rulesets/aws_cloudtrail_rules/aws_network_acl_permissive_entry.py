from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class ACLPermissiveEntry(Rule):
    # src: https://bit.ly/3sfiI87
    id = "7a5fa818-ace8-4ed9-ab03-6a6e01829a2d"
    title = "AWS ACL Permissive Entry"
    description = "AWS ACL created allowing traffic from anywhere"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "high"

    def rule(self, e):
        event = original_get(e)

        # Only check actions creating a new Network ACL entry
        if event.get("eventName") != "CreateNetworkAclEntry":
            return False

        # Check if this new NACL entry is allowing traffic from anywhere
        return (
                deep_get(event, "requestParameters", "cidrBlock") == "0.0.0.0/0"
                and deep_get(event, "requestParameters", "ruleAction") == "allow"
                and deep_get(event, "requestParameters", "egress") is False
        )
