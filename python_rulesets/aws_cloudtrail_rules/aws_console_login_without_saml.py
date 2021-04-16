from python_rules import Rule, deep_get
from _mapping import original_get


class ConsoleLoginNoSAML(Rule):
    # src: https://bit.ly/3a3KtdA
    id = "c3e4e9f8-2e3a-4ab6-8824-5a8cc72ea1b1"
    title = "Console Login Without SAML"
    description = "AWS console login without using SAML"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        account_id = deep_get(event, 'recipientAccountId')
        self.description = f"AWS logins detected without SAML in account [{account_id}]"

        event_name = deep_get(event, 'eventName')
        if event_name != 'ConsoleLogin':
            return False

        additional_event_data = deep_get(event, 'additionalEventData', default={})

        return (
            deep_get(event, 'userIdentity', 'type') != 'AssumedRole'
            and not additional_event_data.get('SamlProviderArn')
        )
