from python_rules import Rule
from _mapping import original_get

# API calls that are indicative of IAM Policy changes
POLICY_CHANGE_EVENTS = {
    "DeleteGroupPolicy",
    "DeleteRolePolicy",
    "DeleteUserPolicy",
    # Put<Entity>Policy is for inline policies.
    # these can be moved into their own rule if inline policies are of a greater concern.
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "CreatePolicy",
    "DeletePolicy",
    "CreatePolicyVersion",
    "DeletePolicyVersion",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
}


class IAMPolicyModified(Rule):
    # src: https://bit.ly/3a32JDN
    id = "eebceecd-b8a9-4fc9-b49e-275b4c670de6"
    title = "AWS IAM Policy Modified"
    description = "AWS IAM policy modified"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return event.get("eventName") in POLICY_CHANGE_EVENTS