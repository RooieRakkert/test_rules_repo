from python_rules import Rule, deep_get
from _mapping import original_get

# API calls that are indicative of KMS CMK Deletion
S3_POLICY_CHANGE_EVENTS = {
    "PutBucketAcl",
    "PutBucketPolicy",
    "PutBucketCors",
    "PutBucketLifecycle",
    "PutBucketReplication",
    "DeleteBucketPolicy",
    "DeleteBucketCors",
    "DeleteBucketLifecycle",
    "DeleteBucketReplication",
}


class AWSS3BucketPolicyModified(Rule):
    # src: https://bit.ly/3dTTsPi
    id = "593c0fec-4f7c-4328-bd9d-43e6a7e80920"
    title = "AWS S3 Bucket Policy Modified"
    description = "AWS S3 bucket policy modification"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        self.description = f"S3 bucket modified by [{deep_get(event, 'userIdentity', 'arn')}]"
        return event.get("eventName") in S3_POLICY_CHANGE_EVENTS and not event.get("errorCode")
