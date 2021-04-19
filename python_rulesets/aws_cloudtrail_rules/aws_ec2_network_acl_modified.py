from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of an EC2 Network ACL modification
EC2_NACL_MODIFIED_EVENTS = {
    "CreateNetworkAcl",
    "CreateNetworkAclEntry",
    "DeleteNetworkAcl",
    "DeleteNetworkAclEntry",
    "ReplaceNetworkAclEntry",
    "ReplaceNetworkAclAssociation",
}


class AWSEC2NetworkACLModified(Rule):
    # src: https://bit.ly/3a52msi
    id = "4df6803b-950b-45e3-92c7-c4f1e36ee35d"
    title = "AWS EC2 Network ACL Modified"
    description = "AWS EC2 network ACL modified"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        return event_name in EC2_NACL_MODIFIED_EVENTS
