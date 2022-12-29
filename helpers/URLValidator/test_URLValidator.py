import unittest
from helpers.URLValidator.URLValidator import URLValidator


class URLValidatorTest(unittest.TestCase):
    def setUp(self):
        self.validator = None

    def test_valid_url(self):
        self.validator = URLValidator('http://www.google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'www.google.com')

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http:www.google.com')

    def test_valid_url_https(self):
        self.validator = URLValidator('https://www.google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'www.google.com')

    def test_invalid_url_https(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('https:www.google.com')

    def test_valid_url_without_protocol(self):
        self.validator = URLValidator('www.google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'www.google.com')

    def test_valid_url_without_www(self):
        self.validator = URLValidator('google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'google.com')

    def test_valid_url_with_path(self):
        validator = URLValidator('www.google.com/meet/20842')
        self.assertEqual(validator.get_url_without_protocol(), 'www.google.com/meet/20842')

    def test_relative_url(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('/meet/20842')

    def test_relative_url_with_protocol(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http:/meet/20842')

    def test_relative_url_with_www(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('www./meet/20842')

    def test_invalid_private_ip_address(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://10.0.0.1')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://172.16.0.1')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://192.168.0.1')

    def test_valid_public_ip_address(self):
        self.validator = URLValidator('http://8.8.8.8')
        self.assertEqual(self.validator.get_url_without_protocol(), '8.8.8.8')
        self.validator = URLValidator('http://64.233.160.0')
        self.assertEqual(self.validator.get_url_without_protocol(), '64.233.160.0')
        self.validator = URLValidator('http://23.253.163.0')
        self.assertEqual(self.validator.get_url_without_protocol(), '23.253.163.0')

    def test_invalid_ip_address_less_than_4_octets(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://1.2.3')

    def test_invalid_ip_address_value_above_255(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://256.2.3.4')

    def test_valid_public_ip_address_without_schema(self):
        self.validator = URLValidator('8.8.8.8')
        self.assertEqual(self.validator.get_url_without_protocol(), '8.8.8.8')

    def test_invalid_private_ip_address_without_schema(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('10.0.0.1')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('172.16.0.1')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('192.168.0.1')

    def test_valid_url_with_query_parameters(self):
        self.validator = URLValidator('http://www.google.com?q=test')
        self.assertEqual(self.validator.get_url_without_protocol(), 'www.google.com?q=test')

    def test_valid_url_with_multiple_query_parameters(self):
        self.validator = URLValidator('http://www.google.com?q=test&param2=value2')
        self.assertEqual(self.validator.get_url_without_protocol(), 'www.google.com?q=test&param2=value2')

    def test_valid_url_with_subdomain(self):
        self.validator = URLValidator('http://subdomain.google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'subdomain.google.com')

    def test_valid_url_with_multiple_subdomains(self):
        self.validator = URLValidator('http://sub1.sub2.google.com')
        self.assertEqual(self.validator.get_url_without_protocol(), 'sub1.sub2.google.com')

    def test_valid_url_with_subdomain_and_query_parameters(self):
        self.validator = URLValidator('http://subdomain.google.com?q=test')
        self.assertEqual(self.validator.get_url_without_protocol(), 'subdomain.google.com?q=test')

    def test_url_with_multiple_subdomains_and_multiple_query_parameters(self):
        validator = URLValidator('http://sub1.sub2.sub3.google.com?param1=value1&param2=value2&param3=value3')
        self.assertEqual(validator.get_url_without_protocol(), 'sub1.sub2.sub3.google.com?param1=value1&param2=value2'
                                                               '&param3=value3')

    def test_invalid_url_with_port(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://www.google.com:8080')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://www.google.com:80')
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http://www.google.com:443')


if __name__ == '__main__':
    unittest.main()
