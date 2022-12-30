import unittest

from helpers.utilities import create_dict_from_list


class TestCreateDictFromList(unittest.TestCase):
    def test_create_dict_from_list(self):
        keys = ['key1', 'key2', 'key3']
        result = create_dict_from_list(keys)
        self.assertDictEqual(result, {'key1': False, 'key2': False, 'key3': False})

    def test_create_dict_from_empty_list(self):
        keys = []
        result = create_dict_from_list(keys)
        self.assertDictEqual(result, {})

    def test_create_dict_from_none(self):
        keys = None
        with self.assertRaises(TypeError):
            create_dict_from_list(keys)


if __name__ == '__main__':
    unittest.main()
