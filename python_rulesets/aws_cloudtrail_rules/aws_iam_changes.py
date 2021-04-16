from python_rules import Rule, deep_get
from _mapping import original_get

IAM_CHANGE_ACTIONS = [
    "Add",
    "Attach",
    "Change",
    "Create",
    "Deactivate",
    "Delete",
    "Detach",
    "Enable",
    "Put",
    "Remove",
    "Set",
    "Update",
    "Upload",
]


class AWSIAMChanges(Rule):
    # src: https://bit.ly/3dZFJXc
    id = "4803a50d-74fc-49ec-84ba-0c67da7ed6fd"
    title = "AWS IAM Changes"
    description = "Changes in AWS IAM"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "low"

    def rule(self, e):
        event = original_get(e)
        source = deep_get(event, 'eventSource')
        if source != "iam.amazonaws.com":
            return False

        event_name = deep_get(event, 'eventName')
        return any((event_name.startswith(action) for action in IAM_CHANGE_ACTIONS))
