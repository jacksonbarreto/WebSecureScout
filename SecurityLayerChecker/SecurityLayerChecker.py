import re
import time
from typing import Type, Dict

import requests
from helpers.URLValidator.URLValidator import URLValidator


def __get_cn_from_issuer_subject(issuer_subject: str) -> str:
    """
    Extract the CN from the issuerSubject string.

    :param issuer_subject: The issuerSubject string.
    :type issuer_subject: str
    :return: The CN.
    :rtype: str
    """
    match = re.search(r"CN=([^,]+)", issuer_subject)
    if match:
        return match.group(1)
    else:
        return ""


class SecurityLayerChecker:

    @staticmethod
    def default_url_base_api() -> str:
        return 'https://api.ssllabs.com/api/v3/analyze/'

    @staticmethod
    def default_params_request_api() -> Dict[str, str]:
        return {
            'host': '',
            'publish': 'on',
            'startNew': 'on',
            'fromCache': 'off',
            'all': 'on'
        }

    @staticmethod
    def get_interface_dict():
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
                'key_size': 2048,
                'key_alg': 'RSA',
                'must_staple': False,
                'sct': False,
                'subject': 'Example Subject',
                'is_valid': False
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
    def __get_cn_from_issuer_subject(issuer_subject: str) -> str:
        """
        Extract the CN from the issuerSubject string.

        :param issuer_subject: The issuerSubject string.
        :type issuer_subject: str
        :return: The CN.
        :rtype: str
        """
        match = re.search(r"CN=([^,]+)", issuer_subject)
        if match:
            return match.group(1)
        else:
            return ""

    @staticmethod
    def __get_result_base_case(vulnerability_code: int) -> str:
        description = ''
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
        return description

    def __init__(self, website: str, url_validator: Type[URLValidator] = URLValidator, timeout_limit: int = 5,
                 url_base_api: str = None, params_request_api: Dict[str, str] = None, request_interval: int = 15):
        self.__website = url_validator(website).get_url_without_protocol()
        self.__url_base_api = SecurityLayerChecker.default_url_base_api() if url_base_api is None else url_base_api
        self.__params_request_api = SecurityLayerChecker.default_params_request_api() if params_request_api is None \
            else params_request_api
        if 'host' not in self.__params_request_api:
            raise ValueError("Missing required key 'host' in 'params request api'")
        self.__params_request_api['host'] = self.__website
        self.__analysis_result = None
        self.__final_result = None
        if timeout_limit <= 0:
            raise ValueError("The timeout limit must be an integer greater than zero")
        self.__timeout_limit = timeout_limit
        if request_interval < 15:
            raise ValueError("The interval must be greater than 15 seconds")
        self.__request_interval = request_interval

    def __request_api(self):
        """
        Make an API request using the specified parameters.

        :return: The result of the API request, as a dictionary.
        :rtype: dict
        :raises requests.exceptions.RequestException: If there is an issue with the API request.
        """
        while True:
            self.__analysis_result = requests.get(url=self.__url_base_api, params=self.__params_request_api).json()
            if self.__analysis_result['status'] == 'READY' or self.__analysis_result['status'] == 'ERROR':
                break
            time.sleep(self.__request_interval)

    def __parse_analysis_result(self):
        if self.__analysis_result is None:
            self.__request_api()
        self.__final_result = self.get_interface_dict()
        self.__parse_supported_ssl_tls_protocols()
        self.__parse_cert_info()
        self.__parse_vulnerabilities()
        self.__final_result['grade'] = self.__analysis_result['endpoints'][0]['grade']

    def __parse_supported_ssl_tls_protocols(self):
        if self.__analysis_result is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        protocols = self.__analysis_result['endpoints'][0]['details']['protocols']

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
        if self.__analysis_result is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        cert = self.__analysis_result['certs'][0]

        self.__final_result['certificate_info']['dns_caa'] = cert['dnsCaa']
        self.__final_result['certificate_info']['issuer'] = \
            SecurityLayerChecker.__get_cn_from_issuer_subject(cert['issuerSubject'])
        self.__final_result['certificate_info']['key_size'] = cert['keySize']
        self.__final_result['certificate_info']['key_alg'] = cert['keyAlg']
        self.__final_result['certificate_info']['must_staple'] = cert['mustStaple']
        self.__final_result['certificate_info']['sct'] = cert['sct']
        self.__final_result['certificate_info']['subject'] = cert['subject']
        if cert['issues'] == 0:
            self.__final_result['certificate_info']['is_valid'] = True

    def __parse_vulnerabilities(self):
        if self.__analysis_result is None:
            self.__request_api()
        if self.__final_result is None:
            self.__parse_analysis_result()

        details = self.__analysis_result['endpoints'][0]['details']

        self.__final_result['vulnerabilities']['beast'] = details['vulnBeast']
        self.__final_result['vulnerabilities']['heartbleed'] = details['heartbleed']
        self.__get_ccs_vulnerability_result_description()
        self.__get_lucky_minus20_vulnerability_result_description()
        self.__get_ticket_bleed_vulnerability_result_description()
        self.__final_result['vulnerabilities']['poodle'] = details['poodle']
        self.__final_result['vulnerabilities']['freak'] = details['freak']

    def __get_ccs_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['openSslCcs']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'possibly vulnerable, but not exploitable'
                case 3:
                    description = 'vulnerable and exploitable'

        self.__final_result['vulnerabilities']['ccs_injection'] = description

    def __get_lucky_minus20_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['openSSLLuckyMinus20']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            description = 'vulnerable and insecure'

        self.__final_result['vulnerabilities']['lucky_minus20'] = description

    def __get_ticket_bleed_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['ticketbleed']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 2:
                    description = 'vulnerable and insecure'
                case 3:
                    description = 'not vulnerable but a similar bug detected'

        self.__final_result['vulnerabilities']['ticket_bleed'] = description

    def __get_bleichenbacher_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['bleichenbacher']
        description = ''

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

        self.__final_result['vulnerabilities']['bleichenbacher'] = description

    def __get_zombie_poodle_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['zombiePoodle']
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
        vulnerability = self.__analysis_result['endpoints'][0]['details']['goldenDoodle']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 4:
                    description = 'vulnerable'
                case 5:
                    description = 'vulnerable and exploitable'

        self.__final_result['vulnerabilities']['golden_doodle'] = description

    def __get_zero_length_padding_oracle_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['zeroLengthPaddingOracle']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 6:
                    description = 'vulnerable'
                case 7:
                    description = 'vulnerable and exploitable'

        self.__final_result['vulnerabilities']['zero_length_padding_oracle'] = description

    def __get_sleeping_poodle_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['sleepingPoodle']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            match vulnerability:
                case 10:
                    description = 'vulnerable'
                case 11:
                    description = 'vulnerable and exploitable'

        self.__final_result['vulnerabilities']['sleeping_poodle'] = description

    def __get_poodle_tls_vulnerability_result_description(self):
        vulnerability = self.__analysis_result['endpoints'][0]['details']['poodleTls']
        description = ''

        if vulnerability <= 1:
            description = SecurityLayerChecker.__get_result_base_case(vulnerability)
        else:
            description = 'vulnerable'

        self.__final_result['vulnerabilities']['poodle_tls'] = description

    def check_security_layer(self):
        if self.__final_result is None:
            self.__parse_analysis_result()
        return self.__final_result
