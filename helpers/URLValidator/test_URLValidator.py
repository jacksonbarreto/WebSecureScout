import unittest
from URLValidator import URLValidator


class URLValidatorTest(unittest.TestCase):
    def setUp(self):
        self.validator = None

    def test_valid_url(self):
        self.validator = URLValidator('http://www.google.com')
        self.assertEqual(self.validator.get_domain(), 'www.google.com')

    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('http:www.google.com')

    def test_valid_url_https(self):
        self.validator = URLValidator('https://www.google.com')
        self.assertEqual(self.validator.get_domain(), 'www.google.com')

    def test_invalid_url_https(self):
        with self.assertRaises(ValueError):
            self.validator = URLValidator('https:www.google.com')

    def test_valid_url_without_protocol(self):
        self.validator = URLValidator('www.google.com')
        self.assertEqual(self.validator.get_domain(), 'www.google.com')

    def test_valid_url_without_www(self):
        self.validator = URLValidator('google.com')
        self.assertEqual(self.validator.get_domain(), 'google.com')

    def test_valid_url_with_path(self):
        validator = URLValidator('www.google.com/meet/20842')
        self.assertEqual(validator.get_domain(), 'www.google.com')


if __name__ == '__main__':
    unittest.main()
