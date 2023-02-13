from typing import Dict, List, Type

import requests
import urllib3

from helpers.URLValidator.URLValidator import URLValidator
from helpers.utilities import lowercase_dict_keys, create_dict_from_list


class SecurityHeadersChecker:

    @staticmethod
    def get_owasp_security_headers() -> List[str]:
        """
            Get a list of OWASP security headers.

            :return: A list of strings containing the names of the OWASP security headers.
            :rtype: list[str]
            """
        return [
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'content-security-policy',
            'x-permitted-cross-domain-policies',
            'referrer-policy',
            'clear-site-data',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy',
            'cache-control'
        ]

    @staticmethod
    def __default_header() -> Dict[str, str]:
        """
          Get a default header for HTTP requests.

          :return: A dictionary containing the default header fields and values.
          :rtype: dict
          """
        return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/108.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,'
                          '*/*;q=0.8, application/signed-exchange;v=b3;q=0.9',
                'Upgrade-Insecure-Requests': '1',
                'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive',
                'Accept-Language': 'en-GB,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,en-US;q=0.6'}

    def __init__(self, website: str, url_validator: Type[URLValidator] = URLValidator,
                 headers_to_check: List[str] = None, timeout_limit: int = 5, header: dict = None):
        """
        Initialize a SecurityHeadersChecker instance.

        :param website: The website to check the security headers.
        :type website: str
        :param url_validator: The URLValidator class to use (defaults to the URLValidator class).
        :type url_validator: type[URLValidator]
        :param headers_to_check: The list of security headers to check (defaults to the list of OWASP security headers).
        :type headers_to_check: list[str]
        :param timeout_limit: The timeout limit for the HTTP requests (defaults to 5 seconds).
        :type timeout_limit: int
        :param header: The header to use for the HTTP requests (defaults to a default header).
        :type header: dict
        """
        urllib3.disable_warnings()
        self.__website = url_validator(website).get_url_without_protocol()
        self.__headers_to_check = SecurityHeadersChecker.get_owasp_security_headers() if headers_to_check is None \
            else headers_to_check
        self.__header = SecurityHeadersChecker.__default_header() if header is None else header
        self.__timeout_limit = timeout_limit
        self.__result_http = None
        self.__result_https = None

    def __check_security_headers(self, protocol: str):
        """
        Check the security headers for the specified protocol.

        :param protocol: The protocol to use for the check (http or https).
        :type protocol: str
        :raises ValueError: If the protocol is invalid.
        :raises requests.exceptions.ConnectionError: If the connection to the website failed.
        """
        protocol = protocol.lower()
        if protocol != 'http' and protocol != 'https':
            raise ValueError('Invalid protocol')

        response = requests.head(f"{protocol}://{self.__website}", headers=self.__header, allow_redirects=False,
                                 verify=False, timeout=self.__timeout_limit)
        lowercase_dict_keys(response.headers)

        for header in self.__headers_to_check:
            if header in response.headers:
                if protocol == 'http':
                    self.__result_http[header] = True
                else:
                    self.__result_https[header] = True

    def check_security_headers_http(self) -> Dict[str, bool]:
        """
        Check the presence of the security headers on the website using the HTTP protocol.

        :return: A dictionary with the security headers as keys and their presence as values (True if the header is
        present, False otherwise).
        :rtype: dict[str, bool]
        :raises ValueError: If the protocol is invalid.
        :raises ConnectionError: If the connection to the website fails.
        :raises TimeoutError: If the connection to the website times out.
        :raises RequestException: If there is an issue with the HTTP request.
        """
        if self.__result_http is None:
            self.__result_http = create_dict_from_list(self.__headers_to_check)
            lowercase_dict_keys(self.__result_http)
            self.__check_security_headers('http')
        return self.__result_http

    def check_security_headers_https(self) -> Dict[str, bool]:
        """
        Check the presence of the security headers on the website using the HTTPS protocol.

        :return: A dictionary with the security headers as keys and their presence as values (True if the header is
        present, False otherwise).
        :rtype: dict[str, bool]
        :raises ValueError: If the protocol is invalid.
        :raises ConnectionError: If the connection to the website fails.
        :raises TimeoutError: If the connection to the website times out.
        :raises RequestException: If there is an issue with the HTTP request.
        """
        if self.__result_https is None:
            self.__result_https = create_dict_from_list(self.__headers_to_check)
            lowercase_dict_keys(self.__result_https)
            self.__check_security_headers('https')
        return self.__result_https

    def get_interface_dict(self) -> Dict[str, bool]:
        """
        Get the format of the results' dictionary.

        :return: A dictionary with the security headers as keys and their presence as values (False for all headers).
        :rtype: dict[str, bool]
        """
        return lowercase_dict_keys(create_dict_from_list(self.__headers_to_check))
