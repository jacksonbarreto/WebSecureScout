import unittest

from helpers.utilities import lowercase_dict_keys


class TestLowercaseDictKeys(unittest.TestCase):
    def test_lowercase_dict_keys(self):
        # Test lowercase keys in a dictionary with mixed case keys
        original_dict = {
            "Key1": "Value1",
            "Key2": "Value2",
            "Key3": "Value3"
        }
        lowercase_dict_keys(original_dict)
        self.assertEqual(original_dict, {
            "key1": "Value1",
            "key2": "Value2",
            "key3": "Value3"
        })

        # Test lowercase keys in a dictionary with all uppercase keys
        original_dict = {
            "KEY1": "Value1",
            "KEY2": "Value2",
            "KEY3": "Value3"
        }
        lowercase_dict_keys(original_dict)
        self.assertEqual(original_dict, {
            "key1": "Value1",
            "key2": "Value2",
            "key3": "Value3"
        })

        # Test lowercase keys in a dictionary with all lowercase keys
        original_dict = {
            "key1": "Value1",
            "key2": "Value2",
            "key3": "Value3"
        }
        lowercase_dict_keys(original_dict)
        self.assertEqual(original_dict, {
            "key1": "Value1",
            "key2": "Value2",
            "key3": "Value3"
        })

        # Test lowercase keys in an empty dictionary
        original_dict = {}
        lowercase_dict_keys(original_dict)
        self.assertEqual(original_dict, {})


if __name__ == "__main__":
    unittest.main()
