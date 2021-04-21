from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class ConsoleLoginFailed(Rule):
    # src: https://bit.ly/3e1LeoG
    id = "1c6ab561-932f-4ca9-93ff-95a72a99a5be"
    title = "Console login failed"
    description = "AWS console login failed"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        accountid = deep_get(event, 'recipientAccountId')
        username = deep_get(event, 'userIdentity', 'userName', default='<UNKNOWN_USER>')
        self.description = f"AWS logins failed in account [{accountid}] by user [{username}]"

        event_name = deep_get(event, 'eventName')
        if event_name != 'ConsoleLogin':
            return False

        user_type = deep_get(event, 'userIdentity', 'type')
        response = deep_get(event, 'responseElements')

        return (event_name == 'ConsoleLogin'
                and user_type == 'IAMUser'
                and deep_get(response, 'ConsoleLogin') == 'Failure')
