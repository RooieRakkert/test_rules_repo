from python_rules import Rule, deep_get
from _mapping import original_get


class AWSRootPasswordChange(Rule):
    # src: https://bit.ly/3a6bqwT
    id = "13596c60-365d-436c-9e80-b0fdb3aef7c2"
    title = "AWS Root Password Change"
    description = "AWS root password changed"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = ['T1098']
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        # Only check password update changes
        if event.get("eventName") != "PasswordUpdated":
            return False

        # Only check root activity
        if deep_get(event, "userIdentity", "type") != "Root":
            return False

        # Only alert if the login was a success
        return deep_get(event, "responseElements", "PasswordUpdated") == "Success"
