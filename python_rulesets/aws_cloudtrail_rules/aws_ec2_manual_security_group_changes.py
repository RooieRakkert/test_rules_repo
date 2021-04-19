from python_rules import Rule, deep_get, pattern_match_list
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

SG_CHANGE_EVENTS = {
    "CreateSecurityGroup": {
        "fields": ["groupName", "vpcId"],
        "title": "New security group [{groupName}] created by {actor}",
    },
    "AuthorizeSecurityGroupIngress": {
        "fields": ["groupId"],
        "title": "User {actor} has updated security group [{groupId}]",
    },
    "AuthorizeSecurityGroupEgress": {
        "fields": ["groupId"],
        "title": "User {actor} has updated security group [{groupId}]",
    },
}
ALLOWED_USER_AGENTS = {
    "* HashiCorp/?.0 Terraform/*",
    # 'console.ec2.amazonaws.com',
    # 'cloudformation.amazonaws.com',
}

ALLOWED_ROLE_NAMES = {
    "Operator",
    "ContinousDeployment",
}

# PROD_ACCOUNT_IDS = {
#     '11111111111111'
# }


class AWSEC2ManualSecurityGroupChanges(Rule):
    # src: https://bit.ly/2QiXN6N
    id = "b5e7344d-7b1a-4782-bd1d-87d6f8bd6d10"
    title = "AWS EC2 Manual Security Group Changes"
    description = "AWS EC2 security group changed"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        if event_name not in SG_CHANGE_EVENTS.keys():
            return False

        # Optional; also add PROD_ACCOUNT_IDS set to check against
        # account_id = flat_get('recipientAccountId')
        # if account_id not in PROD_ACCOUNT_IDS:
        #     return False

        user_agent = deep_get(event, 'userAgent')

        return (
            not(
                pattern_match_list(user_agent, ALLOWED_USER_AGENTS)
                # Validate the IAM Role used is in our acceptable list
                and
                any(role in deep_get(event, "userIdentity", "arn") for role in ALLOWED_ROLE_NAMES)
            )
        )
