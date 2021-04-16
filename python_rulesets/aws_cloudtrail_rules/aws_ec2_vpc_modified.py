from python_rules import Rule, deep_get
from _mapping import original_get

# API calls that are indicative of an EC2 VPC modification
EC2_VPC_MODIFIED_EVENTS = {
    "CreateVpc",
    "DeleteVpc",
    "ModifyVpcAttribute",
    "AcceptVpcPeeringConnection",
    "CreateVpcPeeringConnection",
    "DeleteVpcPeeringConnection",
    "RejectVpcPeeringConnection",
    "AttachClassicLinkVpc",
    "DetachClassicLinkVpc",
    "DisableVpcClassicLink",
    "EnableVpcClassicLink",
}


class AWSEC2VPCModified(Rule):
    # src: https://bit.ly/3g3rK5r
    id = "23e40f08-6859-460a-a79f-df20280223e6"
    title = "AWS EC2 VPC Modified"
    description = "Modification on AWS EC2 VPC"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        return event_name in EC2_VPC_MODIFIED_EVENTS
