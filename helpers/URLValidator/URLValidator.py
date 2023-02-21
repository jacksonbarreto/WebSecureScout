import re


class URLValidator:
    def __init__(self, url: str):
        """
        Initialize a URLValidator object.

        This method receives a string representing a URL and validates if it is a valid URL. If it is valid, it stores
        the URL in the 'url' attribute of the URLValidator object. If it is not valid, it raises a ValueError.

        The URL is considered valid if it has the format 'http(s)://domain.com' or 'http(s)://public_IP_address',
        optionally including subdomain, path, query parameters, and fragment identifier. Private IP address ranges are
        considered invalid.

        :param url: The URL to be validated.
        :type url: str
        :raises ValueError: If the URL is not a string or if it is not a valid URL.
        """
        if url is None:
            raise ValueError('URL attribute is required')
        if not isinstance(url, str):
            raise ValueError('URL attribute must be a string')
        self.url = url.strip()
        url_validation_regex = re.compile(
            r'^(?:(http)s?://)?'  # http:// or https:// (optional)
            r'(?!(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)'  # negative lookahead for private IP address ranges
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # subdomains (optional)
            r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'  # or IP 
            # with range check for each octet 
            r'(?:/\S*)?(?:\?[^\s#]*)?(?:#\S*)?$',  # optional slash, query parameters and fragment identifier
            re.IGNORECASE)
        if re.match(url_validation_regex, self.url):
            self.domain = re.sub(r'^(?:https?://)?|/$', '', self.url).strip()
        else:
            raise ValueError("The provided URL '{}' is not valid. Please provide a valid URL in the format http("
                             "s)://domain.com or http(s)://public_IP_address, optionally including subdomain, path, "
                             "query parameters, and fragment identifier.".format(self.url))

    def get_url_without_protocol(self) -> str:
        """
        Return the domain of the URL string, without the protocol.

        :return: The domain of the URL string.
        :rtype: str
        """
        return self.domain
