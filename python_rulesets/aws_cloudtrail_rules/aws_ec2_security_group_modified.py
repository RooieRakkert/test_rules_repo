from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of an EC2 SecurityGroup modification
EC2_SG_MODIFIED_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
}


class AWSSGModified(Rule):
    # src: https://bit.ly/3e0O4KB
    id = "2b5d5f1e-8590-42a7-8a21-374b0bdd4f15"
    title = "AWS Security Group Modified"
    description = "Modification of AWS Security Group"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        return event_name in EC2_SG_MODIFIED_EVENTS
