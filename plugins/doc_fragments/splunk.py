# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r"""
options:
    splunk_api_username:
        description:
            - The username to authenticate to the Splunk API with
            - This and O(splunk_api_password) must be set if O(splunk_api_auth_token) is not
            - Mutually exclusive with O(splunk_api_auth_token)
        type: str
    splunk_api_password:
        description:
            - The password to authenticate to the Splunk API with
            - This and O(splunk_api_username) must be set if O(splunk_api_auth_token) is not
            - Mutually exclusive with O(splunk_api_auth_token)
        type: str
    splunk_api_auth_token:
        description:
            - A Splunk API user token
            - This must be set if O(splunk_api_username) and O(splunk_api_password) are not set.
            - Mutually exclusive to O(splunk_api_username) and O(splunk_api_password)
        type: str
    validate_certs:
        description:
            - Validate HTTPS certificates.
        type: bool
        default: true
    splunk_api_uri:
        description:
            - The complete uri for the Splunk instance.
        type: str
        required: true
    splunk_api_port:
        description:
            - The port for the Splunk API server.
        type: int
        default: 8089
"""
