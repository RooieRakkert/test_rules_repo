from python_rules import Rule
from test_rules_repo_master.python_rulesets.aws_s3_rules._mapping import original_get

# https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
HTTP_STATUS_CODES_TO_MONITOR = {
    403,  # Forbidden
    405,  # Method Not Allowed
}


class AWSS3AccessError(Rule):
    # src: https://bit.ly/3a9R7Pm
    id = "455be10f-9c77-4fa5-8fa1-9a11b3dd6c62"
    title = "AWS S3 Access Error"
    description = "AWS S3 access error"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)

        if event.get("useragent", "").startswith("aws-internal"):
            return False

        self.description = f"{event.get('httpstatus')} errors found to S3 Bucket [{event.get('bucket')}]"

        return (
                pattern_match(event.get("operation", ""), "REST.*.OBJECT")
                and event.get("httpstatus") in HTTP_STATUS_CODES_TO_MONITOR
        )
