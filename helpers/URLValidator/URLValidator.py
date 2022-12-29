import re


class URLValidator:
    def __init__(self, url):
        self.url = url.strip()
        url_validation_regex = re.compile(
            r'^(?:(http)s?://)?'  # http:// or https:// (optional)
            r'(?!(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)'  # negative lookahead for private IP address ranges
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # subdomains (optional)
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'  # or IP with range check for each octet
            r'(?:/[^\s]*)?(?:\?[^\s#]*)?(?:#\S*)?$',  # optional slash, query parameters and fragment identifier
            re.IGNORECASE)
        if re.match(url_validation_regex, self.url):
            self.domain = re.sub(r'^(?:https?://)?', '', self.url)
        else:
            raise ValueError("The provided URL '{}' is not valid.".format(self.url))

    def get_url_without_protocol(self):
        return self.domain
