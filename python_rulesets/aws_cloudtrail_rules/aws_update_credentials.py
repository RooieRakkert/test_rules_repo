from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

UPDATE_EVENTS = {"ChangePassword", "CreateAccessKey", "CreateLoginProfile", "CreateUser"}


class AWSCredentialsUpdated(Rule):
    # src: https://bit.ly/3wTeiXV
    id = "39349d5d-99fb-49d0-a9c6-113ec0274688"
    title = "AWS Credentials Updated"
    description = "User updated his AWS credentials"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        if event.get("eventName") not in UPDATE_EVENTS:
            return False

        user = deep_get(event, "userIdentity", "userName", default="<UNKNOWN_USER>")
        self.description = f"User {user} has updated has updated their IAM credentials"
        return event.get("eventName") in UPDATE_EVENTS and not event.get("errorCode")
