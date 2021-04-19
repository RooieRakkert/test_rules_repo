from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class RootConsoleLoginFailed(Rule):
    # src: https://bit.ly/3tet49n
    id = "a91d42d4-ff5a-4a14-8aef-4bac390cbe1c"
    title = "Root Console Login Failed"
    description = "AWS console login from root user failed"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "high"

    def rule(self, e):
        event = original_get(e)
        account_id = deep_get(event, 'recipientAccountId')
        source_ip = deep_get(event, 'sourceIPAddress')
        self.description = f"Root AWS login failed on account [{account_id}] from IP [{source_ip}]"

        event_name = deep_get(event, 'eventName')
        if event_name != 'ConsoleLogin':
            return False

        user = deep_get(event, 'userIdentity', 'type')
        if user != 'Root':
            return False

        response_elements = deep_get(event, 'responseElements', {})

        return (
            # Only on failed logins
            response_elements.get("ConsoleLogin") == "Failure"
        )