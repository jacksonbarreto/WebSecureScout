import socket
import requests
from tldextract import extract

from helpers.URLValidator.URLValidator import URLValidator
from helpers.utilities import lowercase_dict_keys


class HTTPSChecker:
    """
    A class to check if a website has HTTPS active, independent of the SSL/TLS certificate validity. This class has
    several public methods to check if HTTPS exists, if there is forced redirection to HTTPS and if the redirection
    is for the same domain.
    """

    @staticmethod
    def get_interface_dict():
        """
        Returns the interface of the HTTPSChecker class in the form of a dictionary. The dictionary contains keys for
        the different HTTPS-related information stored by the class, such as if the website has HTTPS enabled,
        if there is a forced redirection to HTTPS, and if the redirection is for the same domain.
        """
        return {
            HTTPSChecker.HAS_HTTPS_KEY(): None,
            HTTPSChecker.FORCED_REDIRECT_KEY(): None,
            HTTPSChecker.REDIRECT_SAME_DOMAIN_KEY(): None}

    @staticmethod
    def DEFAULT_HEADER():
        return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/108.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,'
                                                                          'application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                                                                          'application/signed-exchange;v=b3;q=0.9',
                'Upgrade-Insecure-Requests': '1',
                'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive',
                'Accept-Language': 'en-GB,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,en-US;q=0.6'}

    @staticmethod
    def HTTP_REDIRECT_CODES():
        return 301, 302, 303, 307, 308

    @staticmethod
    def HTTP_STATUS_CODE_OK():
        return 200

    @staticmethod
    def DEFAULT_HTTPS_PORT():
        return 443

    @staticmethod
    def HAS_HTTPS_KEY():
        return 'has_https'

    @staticmethod
    def FORCED_REDIRECT_KEY():
        return 'forced_redirect_to_https'

    @staticmethod
    def REDIRECT_SAME_DOMAIN_KEY():
        return 'https_redirect_to_same_domain'

    def __init__(self, website, url_validator=URLValidator, timeout_limit=5, header=None):
        self.__website = url_validator(website).get_url_without_protocol()
        self.__timeout_limit = timeout_limit
        self.__header = HTTPSChecker.DEFAULT_HEADER() if header is None else header
        self.__has_https = None
        self.__has_forced_redirect_to_https = None
        self.__has_forced_redirect_to_same_domain = None
        self.__location = None

    def check_https(self):
        """
         Attempts to establish a connection to the website over HTTPS.

         Returns:
             bool: A boolean value indicating whether the connection to the website over HTTPS was successful or not.
         """
        if self.__has_https is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.__timeout_limit)
            try:
                sock.connect((self.__website, HTTPSChecker.DEFAULT_HTTPS_PORT()))
                sock.shutdown(socket.SHUT_RDWR)
                self.__has_https = True
            except ConnectionRefusedError:
                self.__has_https = False
            except Exception as e:
                raise e
            finally:
                sock.close()

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
                response = requests.head(f"http://{self.__website}", headers=self.__header, allow_redirects=False,
                                         verify=False, timeout=self.__timeout_limit)
                lowercase_dict_keys(response.headers)
                if response.status_code in HTTPSChecker.HTTP_REDIRECT_CODES() and \
                        "location" in response.headers and response.headers['location'].startswith("https://"):
                    self.__location = response.headers['location']
                    self.__has_forced_redirect_to_https = True
                elif "strict-transport-security" in response.headers and \
                        response.status_code == HTTPSChecker.HTTP_STATUS_CODE_OK():
                    self.__location = "https://" + self.__website
                    self.__has_forced_redirect_to_https = True
                else:
                    self.__has_forced_redirect_to_https = False
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
        Returns the HTTPS-related information stored by the HTTPSChecker class in the form of a dictionary. The
        dictionary contains keys for the different HTTPS-related information, such as if the website has HTTPS
        enabled, if there is a forced redirection to HTTPS, and if the redirection is for the same domain.
        """
        if self.__has_forced_redirect_to_same_domain is None:
            self.check_forced_redirect_to_same_domain()
        dictionary = HTTPSChecker.get_interface_dict()
        dictionary[HTTPSChecker.HAS_HTTPS_KEY()] = self.__has_https
        dictionary[HTTPSChecker.FORCED_REDIRECT_KEY()] = self.__has_forced_redirect_to_https
        dictionary[HTTPSChecker.REDIRECT_SAME_DOMAIN_KEY()] = self.__has_forced_redirect_to_same_domain
        return dictionary
