from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

# API calls that are indicative of an EC2 Network Gateway modification
EC2_GATEWAY_MODIFIED_EVENTS = {
    "CreateCustomerGateway",
    "DeleteCustomerGateway",
    "AttachInternetGateway",
    "CreateInternetGateway",
    "DeleteInternetGateway",
    "DetachInternetGateway",
}


class AWSEC2GatewayModified(Rule):
    # src: https://bit.ly/3a4MExl
    id = "2abb2100-5276-4c37-8663-26b2fc2d1693"
    title = "AWS EC2 Gateway Modified"
    description = "AWS EC2 gateway modified"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        return event_name in EC2_GATEWAY_MODIFIED_EVENTS
