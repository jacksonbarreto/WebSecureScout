import unittest
from unittest.mock import patch

from SecurityHeadersChecker.SecurityHeadersChecker import SecurityHeadersChecker


class TestSecurityHeadersChecker(unittest.TestCase):
    def setUp(self):
        self.checker = SecurityHeadersChecker('https://www.example.com')

    def test_check_security_headers_https_all_headers(self):
        # Test with a website that has all the security headers
        with patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get') as mock_request:
            mock_request.return_value.headers = {
                'strict-transport-security': 'max-age=31536000; includeSubDomains',
                'x-frame-options': 'DENY',
                'x-content-type-options': 'nosniff',
                'content-security-policy': "default-src 'self'",
                'x-permitted-cross-domain-policies': 'none',
                'referrer-policy': 'strict-origin-when-cross-origin',
                'clear-site-data': '"cache", "cookies", "storage", "executionContexts"',
                'cross-origin-embedder-policy': 'require-corp',
                'cross-origin-opener-policy': 'same-origin',
                'cross-origin-resource-policy': 'same-site',
                'cache-control': 'max-age=31536000, public'
            }
            result = self.checker.check_security_headers_https()
            self.assertDictEqual(result, {
                'strict-transport-security': True,
                'x-frame-options': True,
                'x-content-type-options': True,
                'content-security-policy': True,
                'x-permitted-cross-domain-policies': True,
                'referrer-policy': True,
                'clear-site-data': True,
                'cross-origin-embedder-policy': True,
                'cross-origin-opener-policy': True,
                'cross-origin-resource-policy': True,
                'cache-control': True
            })

    @patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get')
    def test_check_security_headers_https_some_headers(self, mock_head):
        # Test with a website that has some security headers
        with patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get') as mock_request:
            mock_request.return_value.headers = {
                'strict-transport-security': 'max-age=31536000',
                'x-content-type-options': 'nosniff',
                'cache-control': 'max-age=31536000, public'
            }
            result = self.checker.check_security_headers_https()

            self.assertEqual(result, {
                'strict-transport-security': True,
                'x-frame-options': False,
                'x-content-type-options': True,
                'content-security-policy': False,
                'x-permitted-cross-domain-policies': False,
                'referrer-policy': False,
                'clear-site-data': False,
                'cross-origin-embedder-policy': False,
                'cross-origin-opener-policy': False,
                'cross-origin-resource-policy': False,
                'cache-control': True
            })

    def test_check_security_headers_http_all_headers(self):
        # Test with a website that has all the security headers
        with patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get') as mock_request:
            mock_request.return_value.headers = {
                'strict-transport-security': 'max-age=31536000; includeSubDomains',
                'x-frame-options': 'DENY',
                'x-content-type-options': 'nosniff',
                'content-security-policy': "default-src 'self'",
                'x-permitted-cross-domain-policies': 'none',
                'referrer-policy': 'strict-origin-when-cross-origin',
                'clear-site-data': '"cache", "cookies", "storage", "executionContexts"',
                'cross-origin-embedder-policy': 'require-corp',
                'cross-origin-opener-policy': 'same-origin',
                'cross-origin-resource-policy': 'same-site',
                'cache-control': 'max-age=31536000, public'
            }
            result = self.checker.check_security_headers_http()
            self.assertDictEqual(result, {
                'strict-transport-security': True,
                'x-frame-options': True,
                'x-content-type-options': True,
                'content-security-policy': True,
                'x-permitted-cross-domain-policies': True,
                'referrer-policy': True,
                'clear-site-data': True,
                'cross-origin-embedder-policy': True,
                'cross-origin-opener-policy': True,
                'cross-origin-resource-policy': True,
                'cache-control': True
            })

    @patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get')
    def test_check_security_headers_http_some_headers(self, mock_head):
        # Test with a website that has some security headers
        with patch('SecurityHeadersChecker.SecurityHeadersChecker.requests.sessions.Session.get') as mock_request:
            mock_request.return_value.headers = {
                'strict-transport-security': 'max-age=31536000',
                'x-content-type-options': 'nosniff',
                'cache-control': 'max-age=31536000, public'
            }
            result = self.checker.check_security_headers_http()

            self.assertEqual(result, {
                'strict-transport-security': True,
                'x-frame-options': False,
                'x-content-type-options': True,
                'content-security-policy': False,
                'x-permitted-cross-domain-policies': False,
                'referrer-policy': False,
                'clear-site-data': False,
                'cross-origin-embedder-policy': False,
                'cross-origin-opener-policy': False,
                'cross-origin-resource-policy': False,
                'cache-control': True
            })

    def test_get_interface_dict_owasp_headers(self):
        # Test with the OWASP security headers
        result = self.checker.get_interface_dict()
        self.assertDictEqual(result, {
            'strict-transport-security': False,
            'x-frame-options': False,
            'x-content-type-options': False,
            'content-security-policy': False,
            'x-permitted-cross-domain-policies': False,
            'referrer-policy': False,
            'clear-site-data': False,
            'cross-origin-embedder-policy': False,
            'cross-origin-opener-policy': False,
            'cross-origin-resource-policy': False,
            'cache-control': False
        })

    def test_get_interface_dict_custom_headers(self):
        # Test with a custom list of security headers
        custom_headers = ['custom-header-1', 'custom-header-2']
        checker = SecurityHeadersChecker('https://www.example.com', headers_to_check=custom_headers)
        result = checker.get_interface_dict()
        self.assertDictEqual(result, {
            'custom-header-1': False,
            'custom-header-2': False
        })


if __name__ == '__main__':
    unittest.main()
