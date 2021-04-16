from python_rules import Rule, nest_get


class MultipleFailedTLSHandshakes(Rule):
    id = "2f61f27c-9d6a-4f82-a643-fd7d7abe0133"
    title = "Multiple Failed TLS Handshakes"
    description = "Multiple failed TLS handshakes from the same source ip"
    author = "Bouke Hendriks"
    date = "2021/04/08"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        try:
            msg = nest_get(e, 'event.original.message')
        except KeyError:
            return False

        filter_fn = lambda msg: ('TLS hello client' in msg
                                 and ', but unable to complete handshake' in msg)

        # Get count per source-ip
        count = self.stats \
            .groupby('source.ip') \
            .filter(filter_id="tls_handshake", filter_function=filter_fn) \
            .windowed('1m') \
            .get('total_count')
        return count >= 10
