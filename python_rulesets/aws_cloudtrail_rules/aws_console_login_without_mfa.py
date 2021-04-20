from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get


class ConsoleLoginNoMFA(Rule):
    # src: https://bit.ly/3dZpo4U
    id = "9507c37d-7055-4111-9f06-93914bf3b848"
    title = "Console Login Without MFA"
    description = "AWS console login without using MFA"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        account_id = deep_get(event, 'recipientAccountId')
        self.description = f"AWS logins detected without MFA in account [{account_id}]"

        event_name = deep_get(event, 'eventName')
        if event_name != 'ConsoleLogin':
            return False

        additional_event_data = deep_get(event, 'additionalEventData', default={})
        session_context = deep_get(event, 'userIdentity', 'sessionContext', default={})
        response_elements = deep_get(event, 'responseElements', default={})

        return (
            # Only on successful logins
            response_elements.get("ConsoleLogin") == "Success"
            and
            # MFA not in use
            additional_event_data.get("MFAUsed") == "No"
            and
            # Ignore SSO login events
            not additional_event_data.get('SamlProviderArn')
            and
            # And ignoring logins that were authenticated via a session that was itself
            # authenticated with MFA
            deep_get(session_context, "attributes", "mfaAuthenticated") != "true"
        )
