import unittest
from unittest.mock import patch
from HttpsChecker.HttpsChecker import HttpsChecker


class TestHTTPSChecker(unittest.TestCase):
    def setUp(self):
        self.checker = HttpsChecker('https://example.com/')

    @patch('HttpsChecker.HttpsChecker.socket.socket.connect', return_value=None)
    @patch('HttpsChecker.HttpsChecker.socket.socket.shutdown', return_value=None)
    def test_check_https_to_website_with_HTTPS_enabled(self, mock_socket, mock_shutdown):
        # Test connecting to a website with HTTPS enabled
        self.assertTrue(self.checker.check_https())

    @patch('HttpsChecker.HttpsChecker.socket.socket.connect', side_effect=ConnectionRefusedError)
    def test_check_https_to_website_without_HTTPS_enabled(self, mock_socket):
        # Test connecting to a website without HTTPS enabled
        self.assertFalse(self.checker.check_https())

    def test_get_interface_dict_success(self):
        expected_keys = [HttpsChecker.has_https_key(), HttpsChecker.forced_redirect_key(),
                         HttpsChecker.redirect_same_domain_key()]
        expected_values = [None, None, None]
        interface_dict = self.checker.get_interface_dict()
        self.assertCountEqual(interface_dict.keys(), expected_keys)
        self.assertCountEqual(interface_dict.values(), expected_values)

    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_check_forced_redirect_to_https_with_forced_redirect_HTTPS_by_status_code(self, mock_request):
        # Test a website with a forced redirect to HTTPS
        mock_request.return_value.status_code = 301
        mock_request.return_value.headers = {'location': 'https://example.com/'}
        self.assertTrue(self.checker.check_forced_redirect_to_https())

    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_check_forced_redirect_to_https_with_forced_redirect_HTTPS_by_HSTS(self, mock_request):
        # Test a website with a forced redirect to HTTPS by HSTS
        mock_request.return_value.headers = {'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; '
                                                                          'preload'}
        mock_request.return_value.status_code = 200
        self.assertTrue(self.checker.check_forced_redirect_to_https())

    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_check_forced_redirect_to_https_without_forced_redirect_HTTPS(self, mock_request):
        # Test a website without a forced redirect to HTTPS
        mock_request.return_value.status_code = 200
        self.assertFalse(self.checker.check_forced_redirect_to_https())

    @patch('HttpsChecker.HttpsChecker.socket.socket.connect', return_value=None)
    @patch('HttpsChecker.HttpsChecker.socket.socket.shutdown', return_value=None)
    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_check_redirect_to_same_domain_with_same_domain(self, mock_request, mock_shutdown, mock_socket):
        # Test a website with a redirect to the same domain
        mock_request.return_value.status_code = 301
        mock_request.return_value.headers = {'location': 'https://example.com/'}
        self.assertTrue(self.checker.check_forced_redirect_to_same_domain())

    @patch('HttpsChecker.HttpsChecker.socket.socket.connect', return_value=None)
    @patch('HttpsChecker.HttpsChecker.socket.socket.shutdown', return_value=None)
    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_check_redirect_to_same_domain_with_other_domain(self, mock_request, mock_shutdown,
                                                             mock_socket):
        # Test a website with a redirect to a different domain
        mock_request.return_value.status_code = 301
        mock_request.return_value.headers = {'location': 'https://otherdomain.com/'}
        self.assertFalse(self.checker.check_forced_redirect_to_same_domain())

    @patch('HttpsChecker.HttpsChecker.socket.socket.connect', return_value=None)
    @patch('HttpsChecker.HttpsChecker.socket.socket.shutdown', return_value=None)
    @patch('HttpsChecker.HttpsChecker.requests.sessions.Session.get')
    def test_get_https_results(self, mock_request, mock_shutdown, mock_socket):
        # Test a website with a redirect to a different domain
        mock_request.return_value.status_code = 301
        mock_request.return_value.headers = {'location': 'https://example.com/'}
        result = self.checker.get_https_results()
        self.assertTrue(result[HttpsChecker.has_https_key()])
        self.assertTrue(result[HttpsChecker.forced_redirect_key()])
        self.assertTrue(result[HttpsChecker.redirect_same_domain_key()])
