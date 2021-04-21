from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class RootConsoleLogin(Rule):
    # src: https://bit.ly/3wZ3nfs
    id = "e1bbca48-af0a-49e0-a6f3-d32de956e114"
    title = "Root Console Login"
    description = "AWS console login from root user"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "high"

    def rule(self, e):
        event = original_get(e)
        event_name = deep_get(event, 'eventName')
        if event_name != 'ConsoleLogin':
            return False

        user = deep_get(event, 'userIdentity', 'type')
        if user != 'Root':
            return False

        account_id = deep_get(event, 'recipientAccountId')
        source_ip = deep_get(event, 'sourceIPAddress')
        username = deep_get(event, 'userIdentity', 'userName', default='<UNKNOWN_USER>')
        self.description = f"Root AWS logins detected on account [{account_id}] by user [{username}] from IP [{source_ip}]"

        response_elements = deep_get(event, 'responseElements', {})

        return (
            # Only on successful logins
            response_elements.get("ConsoleLogin") == "Success"
        )
