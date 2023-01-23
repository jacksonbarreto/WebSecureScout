from typing import List, Dict, Any



def lowercase_dict_keys(dictionary: Dict[str, Any]) -> Dict[str, Any]:
    """
    Lowercase all the keys in the given dictionary.

    :param dictionary: The dictionary to have the keys lowercase.
    :type dictionary: dict
    :return: The dictionary with the keys lowercase.
    :rtype: dict
    """
    for k in list(dictionary.keys()):
        lowercase_key = k.lower()
        dictionary[lowercase_key] = dictionary.pop(k)
    return dictionary


def create_dict_from_list(keys: List[str]) -> Dict[str, bool]:
    """
    Create a dictionary with the given keys and all values set to False.

    :param keys: The keys for the dictionary.
    :type keys: list[str]
    :return: A dictionary with the given keys and all values set to False.
    :rtype: dict[str, bool]
    """
    return {key: False for key in keys}

