from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get
from ipaddress import ip_address

# Do not alert on these access denied errors for these events.
# Events could be exceptions because they are particularly noisy and provide little to no value,
# or because they are expected as part of the normal operating procedure for certain tools.
EVENT_EXCEPTIONS = {
    "DescribeEventAggregates",  # Noisy, doesn't really provide any actionable info
    "ListResourceTags",  # The audit role hits this when scanning locked down resources
}


class AWSUnauthorizedAPICall(Rule):
    # src: https://bit.ly/3wRnj3D
    id = "cd43b284-b51f-45c5-bf51-66eb9e26668f"
    title = "AWS Unauthorized API call"
    description = "Unauthorized API call on AWS"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        # Validate the request came from outside of AWS
        try:
            ip_address(event.get("sourceIPAddress"))
        except ValueError:
            return False

        self.description = f"Access denied to {deep_get(event, 'userIdentity', 'type')} \
         [user: {deep_get(event, 'userIdentity', 'userName', default='<UNKNOWN_USER>')}, arn: {deep_get(event, 'userIdentity', 'arn')}]"
        return (
                event.get("errorCode") == "AccessDenied" and event.get("eventName") not in EVENT_EXCEPTIONS
        )
