from python_rules import Rule, pattern_match
from _mapping import original_get


class AWSS3InsecureAccess(Rule):
    # src: https://bit.ly/3tdGu5w
    id = "da19173b-efc8-4a69-9362-a8cbf05192b9"
    title = "AWS S3 Insecure Access"
    description = "AWS S3 insecure access detected"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        event = original_get(e)
        self.description = f"Insecure access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"

        return pattern_match(event.get("operation", ""), "REST.*.OBJECT") and (
                not event.get("ciphersuite") or not event.get("tlsVersion")
        )
