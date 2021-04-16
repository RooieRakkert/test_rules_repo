from python_rules import Rule, deep_get
from _mapping import original_get

# API calls that are indicative of an EC2 Route Table modification
EC2_RT_MODIFIED_EVENTS = {
    "CreateRoute",
    "CreateRouteTable",
    "ReplaceRoute",
    "ReplaceRouteTableAssociation",
    "DeleteRouteTable",
    "DeleteRoute",
    "DisassociateRouteTable",
}


class AWSEC2RouteTableModified(Rule):
    # src: https://bit.ly/3dcrLlM
    id = "965d04fb-fb2a-42d8-b0d8-6d7490d03497"
    title = "AWS EC2 Route Table Modified"
    description = "Modification of AWS EC2 routing tables"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        return event_name in EC2_RT_MODIFIED_EVENTS
