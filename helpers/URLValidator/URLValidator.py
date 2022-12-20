import re


class URLValidator:
    def __init__(self, url):
        url_validation_regex = re.compile(
            r'^(?:(http)s?://)?'  # http:// or https:// (optional)
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if re.match(url_validation_regex, url):
            self.url = url
            self.domain = re.findall(r'^(?:https?://)?(?:[^@/\n]+@)?([^:/?\n]+)', url)[0]
        else:
            raise ValueError("The provided URL '{}' is not valid.".format(url))

    def get_domain(self):
        return self.domain
