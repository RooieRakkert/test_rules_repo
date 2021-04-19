from python_rules import Rule, deep_get
from test_rules_repo_master.python_rulesets.aws_cloudtrail_rules._mapping import original_get

S3_DELETE_ACTIONS = {'DeleteBucket', 'DeleteBucketPolicy', 'DeleteBucketWebsite'}


class AWSS3BucketDeleted(Rule):
    # src: https://bit.ly/3dfyFGY
    id = "cac92aed-5953-4c39-9e8e-f782bf29297b"
    title = "AWS S3 Bucket Deleted"
    description = "AWS S3 bucket deleted"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "low"

    def rule(self, e):
        event = original_get(e)
        self.description = f"{deep_get(event, 'userIdentity', 'type')} destroyed a bucket"

        return event.get('eventName') in S3_DELETE_ACTIONS and not event.get("errorCode")
