from python_rules import Rule, deep_get
from _mapping import original_get
from fnmatch import fnmatch
from ipaddress import ip_address

# service/event patterns to monitor
RECON_ACTIONS = {
    "dynamodb": ["List*", "Describe*", "Get*"],
    "ec2": ["Describe*", "Get*"],
    "iam": ["List*", "Get*"],
    "s3": ["List*", "Get*"],
    "rds": ["Describe*", "List*"],
}


class IAMUserReconDenied(Rule):
    # src: https://bit.ly/3a57gWo
    id = "ee55334e-b54c-4a96-ab4e-e8bd0abeabc2"
    title = "AWS IAM User Recon Denied"
    description = "Description"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = ['TA0043']
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        # Filter events
        if event.get("errorCode") != "AccessDenied":
            return False
        if deep_get(event, "userIdentity", "type") != "IAMUser":
            return False

        # Validate the request came from outside of AWS
        try:
            ip_address(event.get("sourceIPAddress"))
        except ValueError:
            return False

        # Pattern match this event to the recon actions
        for event_source, event_patterns in RECON_ACTIONS.items():
            if event.get("eventSource", "").startswith(event_source) and any(
                    fnmatch(event.get("eventName", ""), event_pattern) for event_pattern in event_patterns
            ):
                return True

        user_identity = event.get("userIdentity", {})
        self.description = f"Reconnaissance activity denied to [{user_identity.get('type')}]"

        return False
