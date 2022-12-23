def lowercase_dict_keys(dictionary):
    for k in list(dictionary.keys()):
        lowercase_key = k.lower()
        dictionary[lowercase_key] = dictionary.pop(k)
