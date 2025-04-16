from ansible.module_utils.urls import basic_auth_header
import copy


def splunk_common_argument_spec():
    '''
    Creates a baseline dictionary for connection options
    '''
    return dict(
        splunk_api_username=dict(
            type='str',
            required=False,
        ),
        splunk_api_password=dict(
            type='str',
            required=False,
            no_log=True
        ),
        splunk_api_auth_token=dict(
            type='str',
            required=False,
            no_log=True
        ),
        validate_certs=dict(
            type='bool',
            default=True
        ),
        splunk_api_uri=dict(
            type='str',
            required=True,
        ),
        splunk_api_port=dict(
            type='int',
            default=8089
        )
    )


def splunk_common_required_one():
    '''
    Creates a baseline list of required spec elements
    '''
    return [('splunk_api_username', 'splunk_api_auth_token'), ('splunk_api_password', 'splunk_api_auth_token')]


def splunk_common_mutual_exclusive():
    '''
    Creates a baseline list of mutual exclusive  elements
    '''
    return [('splunk_api_username', 'splunk_api_auth_token'), ('splunk_api_password', 'splunk_api_auth_token')]


def splunk_generate_auth_header(splunk_api_username=None, splunk_api_password=None, token=None):
    '''
    Generates the authentication portion of the header

    Args:
        splunk_api_username (str, optional): The username for basic authentication. Defaults to None.
        splunk_api_password (str, optional): The password for basic authentication. Defaults to None.
        token (str, optional): The API token used for authentication. Defaults to None.

    Returns:
        dict: A dictionary with the requried authentication information that can be appeneded to other headers
    '''

    if token:
        return dict(Authorization=f"Bearer {token}")
    else:
        return dict(Authorization=basic_auth_header(splunk_api_username, splunk_api_password))


def splunk_dict_is_same(dict1, dict2, enforce_list_order=False):
    '''
    Compares two dictionaries and returns if the values are the same or not

    Args:
        dict1 (dict): The first dictionary to compare
        dict2 (dict): The second dictionary to compare
        enforce_list_order (bool, optional): Should list element order be enforced. Defaults to False.

    Returns:
        bool: The dictionaries are the same
    '''

    d1 = copy.deepcopy(dict1)
    d2 = copy.deepcopy(dict2)

    if len(d1.keys()) != len(d2.keys()):
        return False

    for k, v in d1.items():
        if k not in d2:
            return False
        elif isinstance(v, dict):
            # Make sure that the corresponding element is a dict
            if not isinstance(d2[k], dict):
                return False

            if not splunk_dict_is_same(v, d2[k]):
                return False
        elif isinstance(v, list):
            # Make sure that the corresponding element is a list
            if not isinstance(d2[k], list):
                return False

            if not splunk_list_is_same(v, d2[k], enforce_list_order):
                return False
        else:
            if v != d2[k]:
                return False

    return True


def splunk_list_is_same(list1, list2, check_order=False):
    '''
    Compares two lists and returns if the values are the same or not

    Args:
        list1 (list): The first list to compare
        list2 (list): The second list to compare
        check_order (bool, optional): Should element order be enforced. Defaults to False.

    Returns:
        bool: The lists are the same
    '''
    l1 = copy.deepcopy(list1)
    l2 = copy.deepcopy(list2)

    if check_order:
        if len(l1) != len(l2):
            return False
        for idx, element in enumerate(l1):
            if l2[idx] != element:
                return False
    else:
        while len(l1) > 0:
            element = l1.pop(0)
            if element in l2:
                l2.remove(element)
            else:
                return False
        if len(l2) > 0:
            return False

    return True


def splunk_extract_value(content, value, fallback=None):
    '''
    Safely extract a nested value from a dict

    Args:
        content (dict): Dictionary containing the data you hope to extract
        value (str): A period (".") seperated list of nested key values
        fallback (Any, optional): The value to return if the requested key isn't found. Defaults to None.

    Returns:
        Varies: The value of the key requested or None if not found
    '''
    nested_keys = value.split(".")
    tmp = content

    for key in nested_keys:
        tmp = tmp.get(key, None)
        if tmp is None:
            break

    if tmp is None:
        return fallback
    else:
        return tmp


def splunk_sanatize_dict(content, del_keys=None):
    '''
    Remove Empty and specified keys

    Args:
        content (dict): Dictionary to sanitize
        del_keys (list, optional): List of key names to delete. Defaults to None.

    Returns:
        dict: A sanitized dict
    '''
    if del_keys is None:
        del_keys = []

    clean_copy = copy.deepcopy(content)

    for k, v in clean_copy.items():
        if v is None or v == "":
            del_keys.append(k)

    for k in del_keys:
        del clean_copy[k]

    return clean_copy


def splunk_map_fields(content, mappings):
    '''
    Map dictionary values from module key names to API key names

    Args:
        content (dict): Dict containing module keyed data
        mappings (dict): Dict with module key names as the key and API key names as the value

    Returns:
        dict: A translated dict
    '''
    mapped_content = {}

    for k, v in content.items():
        if k in mappings.keys():
            mapped_content[mappings[k]] = v
        else:
            mapped_content[k] = v

    return mapped_content
