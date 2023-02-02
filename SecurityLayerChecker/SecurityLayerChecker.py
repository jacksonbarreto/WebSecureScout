import random
import re
import threading
import time
from typing import Type, Dict, Union

import requests
from requests import Timeout

from helpers.URLValidator.URLValidator import URLValidator
from helpers.utilities import flatten_dictionary


class SecurityLayerChecker:
    current_assessments = 0
    lock_current_assessments = threading.Lock()
    max_assessments = 20
    lock_max_assessments = threading.Lock()

    @classmethod
    def update_max_assessments(cls, value):
        with cls.lock_max_assessments:
            cls.max_assessments = value

    @classmethod
    def update_current_assessments(cls, value):
        with cls.lock_current_assessments:
            cls.current_assessments = value

    @staticmethod
    def get_default_url_base_api() -> str:
        return 'https://api.ssllabs.com/api/v3/analyze/'

    @staticmethod
    def get_default_params_request_api() -> Dict[str, Union[str, int]]:
        return {
            'host': '',
            'publish': 'on',
            'startNew': 'on',
            'fromCache': 'off',
            'all': 'on'
        }

    @staticmethod
    def get_interface_list() -> list[str]:
        """
          Returns the interface list used to store the results of the SSL/TLS analysis.

          :return: The interface list with the structure for storing the SSL/TLS analysis results.
          :rtype: list[str]
        """
        return list(flatten_dictionary(SecurityLayerChecker.get_interface_dict()))

    @staticmethod
    def get_interface_dict() -> Dict[str, Union[str, Dict[str, Union[bool, str]]]]:
        """
        Returns the interface dictionary used to store the results of the SSL/TLS analysis.

        :return: The interface dictionary with the structure for storing the SSL/TLS analysis results.
        :rtype: dict
        """
        return {
            'grade': 'M',
            'ssl_tls_protocol_support': {
                "SSLv2.0": False,
                "SSLv3.0": False,
                "TLSv1.0": False,
                "TLSv1.1": False,
                "TLSv1.2": False,
                "TLSv1.3": False
            },
            'certificate_info': {
                'dns_caa': False,
                'issuer': 'Example Issuer',
                'key_size': 0,
                'key_alg': 'Example RSA',
                'signature_alg': 'Example SHA256withRSA',
                'must_staple': False,
                'sct': False,
                'subject': 'Example Subject',
                'is_valid': False,
                'cert_chain_trust': False
            },
            'vulnerabilities': {
                'beast': False,
                'heartbleed': False,
                'poodle': False,
                'freak': False,
                'ccs_injection': 'unknown',
                'lucky_minus20': 'unknown',
                'ticket_bleed': 'unknown',
                'bleichenbacher': 'unknown',
                'zombie_poodle': 'unknown',
                'golden_doodle': 'unknown',
                'zero_length_padding_oracle': 'unknown',
                'sleeping_poodle': 'unknown',
                'poodle_tls': 'unknown'
            }
        }

    @staticmethod
    def __get_cn_from_issuer_or_subject(issuer_or_subject: str) -> str:
        """
        Extract the CN from the issuerSubject string.

        :param issuer_or_subject: The issuerSubject string.
        :type issuer_or_subject: str
        :return: The CN.
        :rtype: str
        """
        match = re.search(r'CN=([^,]+)', issuer_or_subject)
        if match:
            return match.group(1)
        else:
            return ""

    @staticmethod
    def __get_result_base_case(vulnerability_code: int) -> str:
        match vulnerability_code:
            case -3:
                description = 'timeout'
            case -2:
                description = 'TLS not supported'
            case -1:
                description = 'test failed'
            case 0:
                description = 'unknown'
            case 1:
                description = 'not vulnerable'
            case _:
                raise ValueError(f'Value provided by the API, {vulnerability_code}, '
                                 f'is outside the scope of the documentation')

        return description

    @staticmethod
    def __REQUEST_INTERVAL() -> int:
        return 60

    @staticmethod
    def __TIMEOUT_LIMIT() -> int:
        return 8 * SecurityLayerChecker.__REQUEST_INTERVAL()

    def __init__(self, website: str, url_validator: Type[URLValidator] = URLValidator, url_base_api: str = None,
                 params_request_api: Dict[str, str] = None):
        """
        Initialize a new instance of the SecurityLayerChecker class.

        This method receives the website to be analyzed and optional parameters to specify the URL of the API to be
        used to perform the analysis and the parameters to be included in the API request. If the URL of the API or the
        request parameters are not provided, default values will be used.

        The website parameter is required and must be a string representing the URL of the website to be analyzed.
        The URL must not include the protocol (e.g. "https://"). The URLValidator class will be used to validate the
        website parameter and remove the protocol, if present.

        The url_base_api parameter is optional and must be a string representing the base URL of the API to be used
        to perform the analysis. If not provided, the default value will be used.

        The params_request_api parameter is optional and must be a dictionary with the parameters to be included in
        the API request. If not provided, the default value will be used. The dictionary must include the "host" key,
        representing the website to be analyzed.

        :param str website: The URL of the website to be analyzed.
        :param Type[URLValidator] url_validator: (optional) A class to be used to validate and sanitize the
                website parameter.
        :param str url_base_api: (optional) The base URL of the API to be used to perform the analysis.
        :param dict params_request_api: (optional) The parameters to be included in the API request.
        """

        self.__website = url_validator(website).get_url_without_protocol()
        self.__url_base_api = SecurityLayerChecker.get_default_url_base_api() if url_base_api is None else url_base_api
        self.__params_request_api = SecurityLayerChecker.get_default_params_request_api() if \
            params_request_api is None else params_request_api
        if 'host' not in self.__params_request_api:
            raise ValueError("Missing required key 'host' in 'params request api'")
        self.__params_request_api['host'] = self.__website
        self.__requests_object = requests.get
        self.__result_from_api = None
        self.__final_result = None

    # refactoring the method __request_api
    def __request_api(self):
        """
        Make an API request using the specified parameters.

        :return: The result of the API request, as a dictionary.
        :rtype: dict
        :raises requests.exceptions.RequestException: If there is an issue with the API request.
        :raises exceptions: If querying the API resulted in an error.
        """
        seconds = 0
        time.sleep(random.randint(6, 12))

        while SecurityLayerChecker.current_assessments >= SecurityLayerChecker.max_assessments:
            time.sleep(1)

        while True:
            if seconds > SecurityLayerChecker.__TIMEOUT_LIMIT():
                raise Timeout(f"The API response time has exceeded the {SecurityLayerChecker.__TIMEOUT_LIMIT()} "
                              f"second limit.")

            response = self.__requests_object(url=self.__url_base_api, params=self.__params_request_api)
            self.update_current_assessments(response.headers.get('X-Current-Assessments'))
            self.update_max_assessments(response.headers.get('X-Max-Assessments'))
            print(f'host: {self.__params_request_api["host"]}')
            print(f"Current assessments (classe): {SecurityLayerChecker.current_assessments}")
            print(f"Current assessments: {response.headers.get('X-Current-Assessments')}")
            print(f"Max assessments(classe): {SecurityLayerChecker.max_assessments}")
            print(f"Max assessments: {response.headers.get('X-Max-Assessments')}")
            match response.status_code:
                case 200:
                    self.__result_from_api = response.json()
                    if 'status' in self.__result_from_api:
                        if self.__result_from_api['status'] == 'error':
                            raise Exception(f"The API request resulted in an error: {response.text}")
                        elif self.__result_from_api['status'] == 'ready':
                            break

                case 400:
                    raise ValueError(f"The API request is invalid: {response.text}")
                case 403:
                    raise PermissionError(f"The API request is forbidden: {response.text}")
                case 404:
                    raise ValueError(f"The API request is not found: {response.text}")
                case 429:
                    raise Exception(f"The API request has been throttled: {response.text}")
                case 500:
                    raise Exception(
                        f"The API server encountered an error while processing the request: {response.text}")
                case _:
                    raise Exception(f"An unknown error occurred while querying the API: {response.text}")

            if seconds == 0:
                del self.__params_request_api['startNew']
                self.__params_request_api['fromCache'] = 'on'
                self.__params_request_api['maxAge'] = 1

            time.sleep(SecurityLayerChecker.__REQUEST_INTERVAL())
            seconds += SecurityLayerChecker.__REQUEST_INTERVAL()

    def __request_api1(self):
        """
        Make an API request using the specified parameters.
        :return: The result of the API request, as a dictionary.
        :rtype: dict
        :raises requests.exceptions.RequestException: If there is an issue with the API request.
        :raises exceptions: If querying the API resulted in an error.
        """
        seconds = 0
        while SecurityLayerChecker.current_assessments >= SecurityLayerChecker.max_assessments:
            time.sleep(1)

        while True:
            if seconds > SecurityLayerChecker.__TIMEOUT_LIMIT():
                raise Timeout(f"The API response time has exceeded the {SecurityLayerChecker.__TIMEOUT_LIMIT()} "
                              f"second limit.")

            response = self.__requests_object(url=self.__url_base_api, params=self.__params_request_api)
            match response.status_code:
                case 400:
                    raise Exception('The request was invalid.')
                case 500:
                    raise Exception('The API encountered an error.')
                case 503:
                    raise Exception('The API is currently unavailable.')
                case 529:
                    raise Exception('The API is currently unavailable due to a high load.')

            self.update_current_assessments(response.headers.get('X-Current-Assessments', 0))
            self.update_max_assessments(response.headers.get('X-Max-Assessments', 0))
            self.__result_from_api = response.json()
            print(self.__result_from_api)
            time.sleep(10)
            if self.__result_from_api['status'] == 'READY' or self.__result_from_api['status'] == 'ERROR':
                if self.__result_from_api['status'] == 'ERROR':
                    raise Exception('Querying the API resulted in an error.')
                break

            time.sleep(SecurityLayerChecker.__REQUEST_INTERVAL())
            seconds += SecurityLayerChecker.__REQUEST_INTERVAL()

    def __parse_analysis_result(self):
        if self.__result_from_api is None:
            self.__request_api()
        self.__final_result = self.get_interface_dict()
        self.__parse_supported_ssl_tls_protocols()
        self.__parse_cert_info()
        self.__parse_vulnerabilities()
        self.__final_result['grade'] = self.__result_from_api['endpoints'][0]['grade']

    def __parse_supported_ssl_tls_protocols(self):
        if self.__result_from_api is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        protocols = self.__result_from_api['endpoints'][0]['details']['protocols']

        for protocol in protocols:
            try:
                if protocol['name'] == 'SSL':
                    match protocol['version']:
                        case '2.0':
                            self.__final_result['ssl_tls_protocol_support']['SSLv2.0'] = True
                        case '3.0':
                            self.__final_result['ssl_tls_protocol_support']['SSLv3.0'] = True
                        case _:
                            raise ValueError("Invalid SSL protocol version")
                elif protocol['name'] == 'TLS':
                    match protocol['version']:
                        case '1.0':
                            self.__final_result['ssl_tls_protocol_support']['TLSv1.0'] = True
                        case '1.1':
                            self.__final_result['ssl_tls_protocol_support']['TLSv1.1'] = True
                        case '1.2':
                            self.__final_result['ssl_tls_protocol_support']['TLSv1.2'] = True
                        case '1.3':
                            self.__final_result['ssl_tls_protocol_support']['TLSv1.3'] = True
                        case _:
                            raise ValueError("Invalid TLS protocol version")
                else:
                    raise ValueError("Invalid protocol name")
            except KeyError:
                raise KeyError("Invalid protocol dictionary, missing keys['name' and 'version']")

    def __parse_cert_info(self):
        if self.__result_from_api is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        cert = self.__result_from_api['certs'][0]

        self.__final_result['certificate_info']['dns_caa'] = cert['dnsCaa']
        self.__final_result['certificate_info']['issuer'] = \
            SecurityLayerChecker.__get_cn_from_issuer_or_subject(cert['issuerSubject'])
        self.__final_result['certificate_info']['key_size'] = cert['keySize']
        self.__final_result['certificate_info']['key_alg'] = cert['keyAlg']
        self.__final_result['certificate_info']['signature_alg'] = cert['sigAlg']
        self.__final_result['certificate_info']['must_staple'] = cert['mustStaple']
        self.__final_result['certificate_info']['sct'] = cert['sct']
        self.__final_result['certificate_info']['subject'] = \
            SecurityLayerChecker.__get_cn_from_issuer_or_subject(cert['subject'])
        if cert['issues'] == 0:
            self.__final_result['certificate_info']['is_valid'] = True
        if self.__result_from_api['endpoints'][0]['details']['certChains'][0]['issues'] == 0:
            self.__final_result['certificate_info']['cert_chain_trust'] = True

    def __parse_vulnerabilities(self):
        if self.__result_from_api is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        details = self.__result_from_api['endpoints'][0]['details']

        self.__final_result['vulnerabilities']['beast'] = details['vulnBeast']
        self.__final_result['vulnerabilities']['heartbleed'] = details['heartbleed']
        self.__final_result['vulnerabilities']['poodle'] = details['poodle']
        self.__final_result['vulnerabilities']['freak'] = details['freak']
        self.__get_ccs_vulnerability_result_description()
        self.__get_lucky_minus20_vulnerability_result_description()
        self.__get_ticket_bleed_vulnerability_result_description()
        self.__get_bleichenbacher_vulnerability_result_description()
        self.__get_zombie_poodle_vulnerability_result_description()
        self.__get_golden_doodle_vulnerability_result_description()
        self.__get_zero_length_padding_oracle_vulnerability_result_description()
        self.__get_sleeping_poodle_vulnerability_result_description()
        self.__get_poodle_tls_vulnerability_result_description()

    def __get_ccs_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['openSslCcs']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'possibly vulnerable, but not exploitable'
                case 3:
                    description = 'vulnerable and exploitable'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['ccs_injection'] = description

    def __get_lucky_minus20_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['openSSLLuckyMinus20']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            description = 'vulnerable and insecure'

        self.__final_result['vulnerabilities']['lucky_minus20'] = description

    def __get_ticket_bleed_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['ticketbleed']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'vulnerable and insecure'
                case 3:
                    description = 'not vulnerable but a similar bug detected'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['ticket_bleed'] = description

    def __get_bleichenbacher_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['bleichenbacher']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'vulnerable (weak oracle)'
                case 3:
                    description = 'vulnerable (strong oracle)'
                case 4:
                    description = 'inconsistent results'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['bleichenbacher'] = description

    def __get_zombie_poodle_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['zombiePoodle']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'vulnerable'
                case 3:
                    description = 'vulnerable and exploitable'

        self.__final_result['vulnerabilities']['zombie_poodle'] = description

    def __get_golden_doodle_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['goldenDoodle']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 4:
                    description = 'vulnerable'
                case 5:
                    description = 'vulnerable and exploitable'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['golden_doodle'] = description

    def __get_zero_length_padding_oracle_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['zeroLengthPaddingOracle']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 6:
                    description = 'vulnerable'
                case 7:
                    description = 'vulnerable and exploitable'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['zero_length_padding_oracle'] = description

    def __get_sleeping_poodle_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['sleepingPoodle']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 10:
                    description = 'vulnerable'
                case 11:
                    description = 'vulnerable and exploitable'
                case _:
                    raise ValueError(f'Value provided by the API, {vulnerability}, '
                                     f'is outside the scope of the documentation')

        self.__final_result['vulnerabilities']['sleeping_poodle'] = description

    def __get_poodle_tls_vulnerability_result_description(self):
        vulnerability = self.__result_from_api['endpoints'][0]['details']['poodleTls']

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            description = 'vulnerable'

        self.__final_result['vulnerabilities']['poodle_tls'] = description

    def check_security_layer(self, requests_object: Type[requests.get] = None) \
            -> Dict[str, Union[str, Dict[str, Union[bool, str]]]]:
        """
        Check the security layer of the given URL.

        This method will use the requests_object provided, or the default 'requests.get' object if not provided, to make
        a GET request to the URL passed to the SecurityLayerChecker constructor. The response will be analyzed and a
        dictionary with the results will be returned.

        If this method has already been called before, the previously analyzed results will be returned.

        :param Type[requests.get] requests_object: (optional) Mock of the 'requests.get'
            method to be used in the request.
        :return: A dictionary with the analysis results.
        :rtype: dict
        """
        if requests_object is not None:
            self.__requests_object = requests_object
        if self.__final_result is None:
            self.__parse_analysis_result()
        return self.__final_result

    def check_security_layer_in_list(self):
        result_dict = self.check_security_layer()
        return flatten_dictionary(result_dict)
