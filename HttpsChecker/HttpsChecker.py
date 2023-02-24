import socket
import time
from random import randint

import requests
import urllib3
from requests import ConnectTimeout, ConnectionError
from tldextract import extract

from helpers.URLValidator.URLValidator import URLValidator
from helpers.utilities import lowercase_dict_keys


class HttpsChecker:
    """
    A class to check if a website has HTTPS active, independent of the SSL/TLS certificate validity. This class has
    several public methods to check if HTTPS exists, if there is forced redirection to HTTPS and if the redirection
    is for the same domain.
    """

    @staticmethod
    def get_interface_dict():
        """
        Returns the interface of the HttpsChecker class in the form of a dictionary. The dictionary contains keys for
        the different HTTPS-related information stored by the class, such as if the website has HTTPS enabled,
        if there is a forced redirection to HTTPS, and if the redirection is for the same domain.
        """
        return {
            HttpsChecker.has_https_key(): None,
            HttpsChecker.forced_redirect_key(): None,
            HttpsChecker.redirect_same_domain_key(): None}

    @staticmethod
    def get_interface_list():
        """
        Returns the interface of the HttpsChecker class in the form of a list. The list contains keys for the different
        HTTPS-related information stored by the class, such as if the website has HTTPS enabled, if there is a forced
        redirection to HTTPS, and if the redirection is for the same domain.
        """
        return [
            HttpsChecker.has_http_key(),
            HttpsChecker.has_https_key(),
            HttpsChecker.forced_redirect_key(),
            HttpsChecker.redirect_same_domain_key(),
            HttpsChecker.only_https_key()
        ]

    @staticmethod
    def default_header():
        return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/108.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,'
                                                                          'application/xml;q=0.9,image/avif,'
                                                                          'image/webp,image/apng,*/*;q=0.8,'
                                                                          'application/signed-exchange;v=b3;q=0.9',
                'Upgrade-Insecure-Requests': '1',
                'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive',
                'Accept-Language': 'en-GB,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,en-US;q=0.6'}

    @staticmethod
    def http_redirect_codes():
        return 301, 302, 303, 307, 308

    @staticmethod
    def http_status_code_ok():
        return 200

    @staticmethod
    def default_https_port():
        return 443

    @staticmethod
    def has_https_key():
        return 'has_https'

    @staticmethod
    def forced_redirect_key():
        return 'forced_redirect_to_https'

    @staticmethod
    def redirect_same_domain_key():
        return 'https_redirect_to_same_domain'

    @staticmethod
    def only_https_key():
        return 'only_https'

    @staticmethod
    def has_http_key():
        return 'has_http'

    def __init__(self, website, url_validator=URLValidator, timeout_limit=190, header=None):
        urllib3.disable_warnings()
        self.__website = url_validator(website).get_url_without_protocol_and_path()
        self.__timeout_limit = timeout_limit
        self.__header = HttpsChecker.default_header() if header is None else header
        self.__has_https = None
        self.__has_forced_redirect_to_https = None
        self.__has_forced_redirect_to_same_domain = None
        self.__only_https = False
        self.__has_http = True
        self.__location = None

    def check_https(self):
        """
         Attempts to establish a connection to the website over HTTPS.

         Returns:
             bool: A boolean value indicating whether the connection to the website over HTTPS was successful or not.
         """

        if self.__has_https is None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.__timeout_limit)
                try:
                    sock.connect((self.__website, HttpsChecker.default_https_port()))
                    sock.shutdown(socket.SHUT_RDWR)
                    self.__has_https = True
                except ConnectionRefusedError:
                    self.__has_https = False
                except Exception as e:
                    try:
                        if 'www.' not in self.__website:
                            self.__website = f'www.{self.__website}'
                            sock.connect((f"{self.__website}", HttpsChecker.default_https_port()))
                            sock.shutdown(socket.SHUT_RDWR)
                            self.__has_https = True
                        else:
                            raise e
                    except TimeoutError:
                        self.__has_https = False
                    except socket.gaierror:
                        self.__has_http = False
                        self.__has_https = False
                        self.__has_forced_redirect_to_https = False
                        self.__has_forced_redirect_to_same_domain = False
                        self.__only_https = False
                    except Exception as e:
                        raise e

        return self.__has_https

    def check_forced_redirect_to_https(self):
        """
        Sends an HTTP request to the website and checks if the website redirects to HTTPS.

        Returns:
            bool: A boolean value indicating whether there is a forced redirection to HTTPS or not.
        """
        if self.__has_forced_redirect_to_https is None:
            if self.__has_https is None:
                self.check_https()
            if self.__has_https:
                try:
                    session = requests.Session()
                    session.headers.update(self.__header)
                    response = session.get(f"http://{self.__website}", allow_redirects=False,
                                           timeout=self.__timeout_limit)
                    lowercase_dict_keys(response.headers)
                    if response.status_code in HttpsChecker.http_redirect_codes() and \
                            "location" in response.headers and response.headers['location'].startswith("https://"):
                        self.__location = response.headers['location']
                        self.__has_forced_redirect_to_https = True
                    elif "strict-transport-security" in response.headers and \
                            response.status_code == HttpsChecker.http_status_code_ok():
                        self.__location = f'https://{self.__website}'
                        self.__has_forced_redirect_to_https = True
                    else:
                        self.__has_forced_redirect_to_https = False
                except (ConnectionError, ConnectTimeout):
                    self.__has_forced_redirect_to_https = False
                    self.__has_forced_redirect_to_same_domain = False
                    self.__only_https = True
                    self.__has_http = False
            else:
                self.__has_forced_redirect_to_https = False
        return self.__has_forced_redirect_to_https

    def check_forced_redirect_to_same_domain(self):
        """
        Sends an HTTP request to the website and checks if the redirection to HTTPS is for the same domain.

        Returns:
            bool: A boolean value indicating whether the redirection to HTTPS is for the same domain or not.
        """
        if self.__has_forced_redirect_to_same_domain is None:
            if self.__has_forced_redirect_to_https is None:
                self.check_forced_redirect_to_https()

            if self.__has_forced_redirect_to_https:
                _, td_location, tsu_location = extract(self.__location)
                _, td_origin, tsu_origin = extract(str(self.__website))
                redirect_domain = f"{td_location}.{tsu_location}"
                origin_domain = f"{td_origin}.{tsu_origin}"
                if redirect_domain == origin_domain:
                    self.__has_forced_redirect_to_same_domain = True
                else:
                    self.__has_forced_redirect_to_same_domain = False
            else:
                self.__has_forced_redirect_to_same_domain = False

        return self.__has_forced_redirect_to_same_domain

    def get_https_results(self):
        """
        Returns the HTTPS-related information stored by the HttpsChecker class in the form of a dictionary. The
        dictionary contains keys for the different HTTPS-related information, such as if the website has HTTPS
        enabled, if there is a forced redirection to HTTPS, and if the redirection is for the same domain.
        """
        if self.__has_forced_redirect_to_same_domain is None:
            self.check_forced_redirect_to_same_domain()
        dictionary = HttpsChecker.get_interface_dict()
        dictionary[HttpsChecker.has_http_key()] = self.__has_http
        dictionary[HttpsChecker.has_https_key()] = self.__has_https
        dictionary[HttpsChecker.forced_redirect_key()] = self.__has_forced_redirect_to_https
        dictionary[HttpsChecker.redirect_same_domain_key()] = self.__has_forced_redirect_to_same_domain
        dictionary[HttpsChecker.only_https_key()] = self.__only_https
        return dictionary
