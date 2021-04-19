from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class AWSRootLoginFailed(Rule):
    # src: https://bit.ly/3mWgYQ9
    id = "2f2d45c4-092c-4040-b7e6-12de9aac9a6d"
    title = "AWS Root Login Failed"
    description = "AWS console failed root login"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        # Only check console logins
        if event.get("eventName") != "ConsoleLogin":
            return False

        # Only check root activity
        if deep_get(event, "userIdentity", "type") != "Root":
            return False

        # Only alert if the login was a failure
        return deep_get(event, "responseElements", "ConsoleLogin") != "Success"
