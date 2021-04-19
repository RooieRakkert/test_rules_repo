from python_rules import Rule
from test_rules_repo_master.python_rulesets.aws_vpc_flow_rules._mapping import original_get


class AWSVPCHealthyLogStatus(Rule):
    # src: https://bit.ly/3wWTYEU
    id = "8ed3e71f-5f6c-4417-afe8-c951d439a967"
    title = "AWS VPC Healthy Log Status"
    description = "AWS VPC healthy log status"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        return event.get("log-status") == "SKIPDATA"
