from python_rules import Rule, nest_get


class DifferentLocationsForSingleUser(Rule):
    id = "c583112a-ef66-47b7-b73a-a17079109f61"
    title = "Different locations for single user"
    description = "A user has executed actions from more than one location over the span of a week"
    author = "Florentijn Knol"
    date = "2021/03/30"
    tags = ['attack.T1078']
    status = "experimental"
    level = "medium"

    def rule(self, e):
        nr_locations_per_user = \
            self.stats.groupby("aws.cloudtrail.user_identity.arn").windowed("7d").get("n_unique",
                                                                                          'source.geo.city_name')
        try:
            user = nest_get(e, "aws.cloudtrail.user_identity.arn")
            location = nest_get(e, 'source.geo.city_name')
        except KeyError:
            return False

        exclude_users = [
            "arn:aws:sts::561306761274:assumed-role/cognito_unauthenticated_prod/CognitoIdentityCredentials",
            "arn:aws:iam::561306761274:root"
        ]

        if user not in exclude_users and (nr_locations_per_user is not None and nr_locations_per_user > 1):
            return True
        return False


class MultipleAccessDenied(Rule):
    id = "551e01cc-a0b7-4b92-8634-4f9e307df3fd"
    title = "Multiple Denied Access"
    description = "User has more than 5 access denied or unauthorized events in a day."
    author = "Bouke Hendriks"
    date = "2021/04/06"
    tags = ['attack.TA0043']
    status = "experimental"
    level = "medium"

    def rule(self, e):
        nr_access_denied_per_user = \
            self.stats.groupby('aws.cloudtrail.user_identity.arn').windowed('1d').get('count',
                                                                                      'aws.cloudtrail.error_code')
        try:
            user = nest_get(e, "aws.cloudtrail.user_identity.arn")
            error_code = nest_get(e, 'aws.cloudtrail.error_code')
        except KeyError:
            return False

        if not (('UnauthorizedOperation' in error_code) or ('AccessDenied' in error_code)):
            return False

        if (nr_access_denied_per_user is not None and nr_access_denied_per_user > 5):
            return True
        return False


class MultipleFailedLogins(Rule):
    id = "e7012fa2-cafb-44a6-a998-2510b15484b3"
    title = "Multiple Failed Logins"
    description = "User has more than 5 failed authentication responses on console login events"
    author = "Bouke Hendriks"
    date = "2021/04/07"
    tags = ['attack.TA0006', 'attack.T1110']
    status = "experimental"
    level = "medium"

    def rule(self, e):
        nr_failed_login = \
            self.stats.groupby('user.name').windowed('1d').get('count', 'aws.cloudtrail.error_message')

        try:
            user = nest_get(e, 'user.name')
            event_action = nest_get(e, 'event.action')
            err_msg = nest_get(e, 'aws.cloudtrail.error_message')
        except KeyError:
            return False

        if (event_action == 'ConsoleLogin') and (err_msg == 'Failed authentication'):
            if (nr_failed_login is not None) and (nr_failed_login > 3):
                return True
        return False


# class HighNumberActionsComparedToMean(Rule):
#     id = "accce288-d26e-4358-9458-c997043f153a"
#     title = "Large amount of unique actions by user"
#     description = "User's daily amount of unique actions divert more than 2x stddev compared to mean users"
#     author = "Bouke Hendriks"
#     date = "2021/04/07"
#     tags = []
#     status = "experimental"
#     level = "medium"
#
#     def rule(self, e):
#         count_actions = \
#             self.stats.groupby('user.name').windowed('1d').get('count', 'event.action')
#         mean_actions = \
#             self.stats.groupby('user.name').windowed('1d').get('mean_count', 'event.action')
#
#         stddev_actions = \
#             self.stats.groupby('user.name').windowed('1d').get('std_count', 'event.action')
#
#         anom_factor = 2
#         if np.isnan(stddev_actions):
#             return False
#
#         # These limits will be updated on every new instance
#         upper_boundary = mean_actions + (anom_factor * stddev_actions)
#         lower_boundary = mean_actions - (anom_factor * stddev_actions)
#
#         # if count is outside of boundaries we return True
#         return not lower_boundary < count_actions < upper_boundary


class UserMultipleIPaddresses(Rule):
    id = "3218561c-852b-4874-bcb7-ec74e1296ecd"
    title = "Large number IP for user"
    description = "More than three IP addresses used for the same user within one hour"
    author = "Bouke Hendriks"
    date = "2021/04/07"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        n_unique_ips = self.stats.groupby('user.name').windowed('1h').get('n_unique', 'source.ip')
        return n_unique_ips > 3


class MultipleAccountsSameIPaddress(Rule):
    id = "35be2fa0-c0c4-4ff3-adc8-dde89d2a6e3b"
    title = "Multiple accounts on same IP used"
    description = "Same IP address is associated with more than 3 accounts"
    author = "Bouke Hendriks"
    date = "2021/04/07"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        n_unique_users = self.stats.groupby('source.ip').windowed('1h').get('n_unique', 'user.name')
        return n_unique_users > 3


# class HighCountServiceProviderByUser(Rule):
#     id = "89924df8-b082-4785-9b09-6a465bf183f1"
#     title = "High use specific service provider"
#     description = "User has a large amount of logs of a certain service provider, " \
#                   "compared to the mean of users for this provider"
#     author = "Bouke Hendriks"
#     date = "2021/04/07"
#     tags = []
#     status = "experimental"
#     level = "medium"
#
#     def rule(self, e):
#         count = \
#             self.stats.groupby('user.name').windowed('1d').get('count', 'event.provider')
#         mean_count = \
#             self.stats.groupby('user.name').windowed('1d').get('mean_count', 'event.provider')
#
#         std_count = \
#             self.stats.groupby('user.name').windowed('1d').get('std_count', 'event.provider')
#
#         anom_factor = 2
#         if np.isnan(std_count):
#             return False
#         return count > (anom_factor*std_count + mean_count)


class LargeNuniqueServiceProvidersByUser(Rule):
    id = "adbf501d-d614-44a4-9999-dc74856bfb89"
    title = "High n-unique service providers by user"
    description = "User has > 5 unique service providers used this hour"
    author = "Bouke Hendriks"
    date = "2021/04/07"
    tags = []
    status = "experimental"
    level = "medium"

    def rule(self, e):
        n_unique_providers = \
            self.stats.groupby('user.name').windowed('1h').get('n_unique', 'event.provider')

        return n_unique_providers > 5


class AccountEnumerationAWS(Rule):
    title = "Account Enumeration on AWS"
    id = "e9c14b23-47e2-4a8b-8a63-d36618e33d70"
    status = "experimental"
    description = "Detects enumeration of accounts configuration via api call to list different instances and " \
                  "services within a short period of time/"
    author = "toffeebr33k"
    date = "2021/06/04"
    level = "low"
    tags = [
        "attack.discovery",
        "attack.t1592"
        ]

    def rule(self, e):
        filter_fn = lambda x: "list" in nest_get(x, 'event.action').lower()
        total_count = \
            self.stats.filter(filter_id="list_filter",
                              filter_function=filter_fn).windowed("10m").get("total_count")
        try:
            if filter_fn(e) and total_count is not None and total_count > 50:
                return True
        except KeyError:
            return False

        return False

