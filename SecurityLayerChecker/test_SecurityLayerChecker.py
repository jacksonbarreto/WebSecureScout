import unittest

import requests

from SecurityLayerChecker.SecurityLayerChecker import SecurityLayerChecker
from unittest.mock import patch, MagicMock


def update_dict_recursive(d, k, v):
    for key, value in d.items():
        if isinstance(value, dict):
            update_dict_recursive(value, k, v)
        elif isinstance(value, list):
            for dct in value:
                if isinstance(dct, dict):
                    update_dict_recursive(dct, k, v)
        if key == k:
            d[key] = v


def get_response(**kwargs):
    response = {
        'status': 'READY',
        'endpoints': [
            {
                'grade': 'T',
                'details': {
                    'certChains': [
                        {
                            'issues': 0
                        }
                    ],
                    'protocols': [
                        {
                            'name': 'TLS',
                            'version': '1.0'
                        }
                    ],
                    'vulnBeast': False,
                    'heartbleed': False,
                    'openSslCcs': 1,
                    'openSSLLuckyMinus20': 1,
                    'ticketbleed': 1,
                    'bleichenbacher': 1,
                    'poodle': False,
                    'poodleTls': 1,
                    'freak': False,
                    'zeroLengthPaddingOracle': 1,
                    'goldenDoodle': 4,
                    'zombiePoodle': 2,
                    'sleepingPoodle': 11
                }
            }
        ],
        'certs': [
            {
                'subject': "CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US",
                'issuerSubject': "CN=DigiCert SHA2 Secure Server CA, O=DigiCert Inc, C=US",
                'sigAlg': "SHA256withRSA",
                'dnsCaa': False,
                'mustStaple': False,
                'issues': 0,
                'sct': True,
                'keyAlg': 'RSA',
                'keySize': 2048
            }
        ]
    }

    for key, value in kwargs.items():
        update_dict_recursive(response, key, value)
    return response


class TestSecurityLayerChecker(unittest.TestCase):
    def setUp(self):
        self.checker = SecurityLayerChecker('https://www.example.com')
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.headers = {'X-Current-Assessments': 1, 'X-Max-Assessments': 20}
        self.mock_request = MagicMock(spec=requests.get)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_supported_ssl_tls_protocol(self, mock_sleep, mock_request):
        setup_response = [
            {
                'name': 'TLS',
                'version': '1.0'
            },
            {
                'name': 'TLS',
                'version': '1.1'
            },
            {
                'name': 'SSL',
                'version': '2.0'
            },
        ]

        self.mock_response.json.return_value = get_response(protocols=setup_response)
        self.mock_request.return_value = self.mock_response

        result = self.checker.check_security_layer(requests_object=self.mock_request)

        expected_result = {
            'TLSv1.0': True,
            'TLSv1.1': True,
            'TLSv1.2': False,
            'TLSv1.3': False,
            'SSLv2.0': True,
            'SSLv3.0': False
        }
        self.assertDictEqual(result['ssl_tls_protocol_support'], expected_result)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_parse_vulnerabilities(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response(vulnBeast=True, poodleTls=3, sleepingPoodle=11)

        mock_request.return_value = self.mock_response

        result = self.checker.check_security_layer(requests_object=mock_request)

        expected_result = {
            'beast': True,
            'heartbleed': False,
            'poodle': False,
            'freak': False,
            'ccs_injection': 'not vulnerable',
            'lucky_minus20': 'not vulnerable',
            'ticket_bleed': 'not vulnerable',
            'bleichenbacher': 'not vulnerable',
            'zombie_poodle': 'vulnerable',
            'golden_doodle': 'vulnerable',
            'zero_length_padding_oracle': 'not vulnerable',
            'sleeping_poodle': 'vulnerable and exploitable',
            'poodle_tls': 'vulnerable'
        }
        self.assertDictEqual(result['vulnerabilities'], expected_result)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_vulnerabilities_invalid_value_from_api(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response(poodleTls=-8)
        self.mock_request.return_value = self.mock_response
        with self.assertRaises(ValueError):
            self.checker.check_security_layer(requests_object=self.mock_request)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_openSslCcs_vulnerabilities_invalid_value_from_api(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response(openSslCcs=5)
        self.mock_request.return_value = self.mock_response
        with self.assertRaises(ValueError):
            self.checker.check_security_layer(requests_object=self.mock_request)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_ticketbleed_vulnerabilities_invalid_value_from_api(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response(ticketbleed=5)
        self.mock_request.return_value = self.mock_response
        with self.assertRaises(ValueError):
            self.checker.check_security_layer(requests_object=self.mock_request)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_cert_info_valid(self, mock_sleep, mock_request):
        setup_response = [
            {
                'subject': "CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US",
                'issuerSubject': "CN=DigiCert SHA2 Secure Server CA, O=DigiCert Inc, C=US",
                'sigAlg': "SHA256withRSA",
                'dnsCaa': False,
                'mustStaple': False,
                'issues': 0,
                'sct': False,
                'keyAlg': 'RSA',
                'keySize': 2048
            }
        ]
        self.mock_response.json.return_value = get_response(certs=setup_response)
        self.mock_request.return_value = self.mock_response
        result = self.checker.check_security_layer(requests_object=self.mock_request)
        expected_result = {
            'dns_caa': False,
            'issuer': 'DigiCert SHA2 Secure Server CA',
            'key_size': 2048,
            'key_alg': 'RSA',
            'signature_alg': 'SHA256withRSA',
            'must_staple': False,
            'sct': False,
            'subject': '*.badssl.com',
            'is_valid': True,
            'cert_chain_trust': True
        }
        self.assertDictEqual(result['certificate_info'], expected_result)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_cert_info_invalid(self, mock_sleep, mock_request):
        setup_response = [
            {
                'subject': "CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US",
                'issuerSubject': "CN=DigiCert SHA2 Secure Server CA, O=DigiCert Inc, C=US",
                'sigAlg': "SHA256withRSA",
                'dnsCaa': False,
                'mustStaple': False,
                'issues': 3,
                'sct': False,
                'keyAlg': 'RSA',
                'keySize': 2048
            }
        ]
        self.mock_response.json.return_value = get_response(certs=setup_response)
        self.mock_request.return_value = self.mock_response
        result = self.checker.check_security_layer(requests_object=self.mock_request)
        expected_result = {
            'dns_caa': False,
            'issuer': 'DigiCert SHA2 Secure Server CA',
            'key_size': 2048,
            'key_alg': 'RSA',
            'signature_alg': 'SHA256withRSA',
            'must_staple': False,
            'sct': False,
            'subject': '*.badssl.com',
            'is_valid': False,
            'cert_chain_trust': True
        }
        self.assertDictEqual(result['certificate_info'], expected_result)

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_cert_chain_info_invalid(self, mock_sleep, mock_request):
        setup_response = [{'issues': 12}]
        self.mock_response.json.return_value = get_response(certChains=setup_response)
        self.mock_request.return_value = self.mock_response
        result = self.checker.check_security_layer(requests_object=self.mock_request)
        self.assertFalse(result['certificate_info']['cert_chain_trust'])

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_issuer_name(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response()
        self.mock_request.return_value = self.mock_response
        result = self.checker.check_security_layer(requests_object=self.mock_request)
        self.assertEqual(result['certificate_info']['issuer'], 'DigiCert SHA2 Secure Server CA')

    @patch("SecurityLayerChecker.SecurityLayerChecker.requests.get")
    @patch("SecurityLayerChecker.SecurityLayerChecker.time.sleep", return_value=None)
    def test_parse_subject_name(self, mock_sleep, mock_request):
        self.mock_response.json.return_value = get_response()
        self.mock_request.return_value = self.mock_response
        result = self.checker.check_security_layer(requests_object=self.mock_request)
        self.assertEqual(result['certificate_info']['subject'], '*.badssl.com')

    def test_invalid_params_request(self):
        params_request = {'key1': 'value1'}
        with self.assertRaises(ValueError):
            SecurityLayerChecker('https://www.example.com', params_request_api=params_request)


if __name__ == '__main__':
    unittest.main()
