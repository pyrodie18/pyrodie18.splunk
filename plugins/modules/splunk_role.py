#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Troy Ward
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: splunk_role
short_description: Create/update/delete Splunk roles
description:
    - Create/update/delete Splunk roles.
author:
    - "Troy Ward (@pyrodie18)"
requirements:
    - "python >= 3.11"
version_added: '1.0.0'
options:
    name:
        description:
            - The name of the role being created/modified/deleted
        required: true
        type: str
    state:
        description:
            - V(present) - create/update role.
            - V(absent) - delete user.
        choices: [present, absent]
        default: "present"
        type: str
    capabilities:
        description:
            - A list of specified capabilities to attach to the role.
        type: list
        elements: str
    role_realtime_limit:
        description:
            - The total number of real-time searches for all members in the role.
            - Use '0' for unlimited.
        type: int
    role_total_limit:
        description:
            - The total number of searches for all members in the role.
            - Use '0' for unlimited.
        type: int
    app:
        description:
            - The folder name of the app to use as the default app for this role.
            - A user-specific default app overrides this.
        type: str
    imported_roles:
        description:
            - Roles (with their capabilities and limits) to import into the role.
        type: list
        elements: str
    disk_quota:
        description:
            - The max disk space in MB that can be used by a user's search jobs.
        type: int
    filter:
        description:
            - Search string that restricts the scope of searches run by this role.
        type: str
    allowed_indexes:
        description:
            - A list of indexes that this role is allowed to search.
            - May use wildcards
            - Internal indexes must be wildcarded with '_*'
        type: list
        elements: str
    default_indexes:
        description:
            - A list of indexes that this role searches by default.
            - May use wildcards
            - Internal indexes must be wildcarded with '_*'
        type: list
        elements: str
    user_realtime_limit:
        description:
            - Number of real-time searches the user is limited to.
            - Use '0' for unlimited.
        type: int
    user_total_limit:
        description:
            - Number of searches the user is limited to.
            - Use '0' for unlimited.
        type: int
    time_limit:
        description:
            - Maximum number (in seconds) that this role is able to search.
            - Set to V(unlimisted) for no limits
        type: str
    earliest_search:
        description:
            - The earliest searchable event (in seconds) that this role is able to search.
            - Set to V(unlimisted) for no limits
        type: str

extends_documentation_fragment:
    - pyrodie18.splunk.splunk

"""

EXAMPLES = """
---
# Create a new role
- name: Create test_role
  pyrodie18.splunk.splunk_role:
    name: test_role
    state: present
    imported_roles:
        - user
        - admin
    default_indexes:
        - '*'
        - '_*'
    allowed_indexes:
        - '*'
        - '_*'
    time_limit: unlimited
    splunk_api_user: admin
    splunk_api_password: 'PASSword123!@#'
    splunk_api_uri: https://localhost

# Delete role
- name: Delete test_role
  pyrodie18.splunk.splunk_role:
    name: test_role
    state: absent

"""

from ansible_collections.pyrodie18.splunk.plugins.module_utils.base import SplunkBase
import ansible_collections.pyrodie18.splunk.plugins.module_utils.helpers as SplunkHelpers
from ansible.module_utils.basic import AnsibleModule


class SplunkRole(SplunkBase):
    SERVICE_PATH = "/authorization/roles"
    FIELD_MAPPING = {
        "role_realtime_limit": "cumulativeRTSrchJobsQuota",
        "role_total_limit": "cumulativeSrchJobsQuota",
        "app": "defaultApp",
        "user_realtime_limit": "rtSrchJobsQuota",
        "disk_quota": "srchDiskQuota",
        "filter": "srchFilter",
        "allowed_indexes": "srchIndexesAllowed",
        "default_indexes": "srchIndexesDefault",
        "user_total_limit": "srchJobsQuota",
        "time_limit": "srchTimeWin",
        "earliest_search": "srchTimeEarliest",
    }

    def __init__(self, module):
        super().__init__(module)
        self.rolename = self.module.params['name']

    def role_exists(self, rolename=None):
        '''
        Checks to see if the specified user already exists

        return:  The user information if found or False if not found
        '''
        if not rolename:
            rolename = self.module.parms['name']
        search_path = f"{self.SERVICE_PATH}/{rolename}"
        response = self.send_request(
            self.module, search_path, catch_404=True)

        if response['status'] == 404:
            return False

        content = response["content"].parsed(key="feed.entry")[0]
        mod_resp = self._build_response(content)
        return mod_resp

    def delete_role(self):
        '''
        Deletes the user specified in the module
        '''
        service_path = f"{self.SERVICE_PATH}/{self.rolename}"
        response = self.send_request(
            self.module, service_path, method="DELETE")

    def create_role(self):
        input_data = self._build_input()
        input_data = SplunkHelpers.splunk_sanatize_dict(input_data)
        input_data = SplunkHelpers.splunk_map_fields(
            input_data, self.FIELD_MAPPING)

        response = self.send_request(
            self.module, self.SERVICE_PATH, input_data, method="POST")
        content = response["content"].parsed(key="feed.entry")[0]
        mod_resp = self._build_response(content)
        return mod_resp

    def modify_role(self, current_state):
        desired_state = self._build_input()

        # Cleanup fields that breack sameness check and compare
        desired_state = SplunkHelpers.splunk_sanatize_dict(
            desired_state, ['name'])
        current_state = SplunkHelpers.splunk_sanatize_dict(
            current_state, ['name'])
        if SplunkHelpers.splunk_dict_is_same(desired_state, current_state):
            self.module.exit_json(
                stdout="Role present, no change required", changed=False)

        desired_state = SplunkHelpers.splunk_map_fields(
            desired_state, self.FIELD_MAPPING)

        service_path = f"{self.SERVICE_PATH}/{self.rolename}"
        response = self.send_request(
            self.module, service_path, desired_state, method="POST")
        self.module.exit_json(
            stdout=f"Role {self.rolename}, configuration updated", changed=True)

    def _build_response(self, contents):
        '''
        Build response dictionary

        Args:
            contents (dict): Dictionary containing all return values from query

        Returns:
            dict: Response information
        '''
        response = {}
        response['name'] = SplunkHelpers.splunk_extract_value(
            contents, "name", None)
        response['capabilities'] = SplunkHelpers.splunk_extract_value(
            contents, "content.capabilities", None)
        response['role_realtime_limit'] = SplunkHelpers.splunk_extract_value(
            contents, "content.cumulativeRTSrchJobsQuota", None)
        response['role_total_limit'] = SplunkHelpers.splunk_extract_value(
            contents, "content.cumulativeSrchJobsQuota", None)
        response['app'] = SplunkHelpers.splunk_extract_value(
            contents, "content.defaultApp", None)
        response['imported_roles'] = SplunkHelpers.splunk_extract_value(
            contents, "content.imported_roles", None)
        response['disk_quota'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchDiskQuota", None)
        response['filter'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchFilter", None)
        response['allowed_indexes'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchIndexesAllowed", None)
        response['default_indexes'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchIndexesDefault", None)
        response['user_realtime_limit'] = SplunkHelpers.splunk_extract_value(
            contents, "content.rtSrchJobsQuota", None)
        response['user_total_limit'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchJobsQuota", None)
        response['time_limit'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchTimeWin", None)
        response['earliest_search'] = SplunkHelpers.splunk_extract_value(
            contents, "content.srchTimeEarliest", None)

        return response

    def _build_input(self):
        '''
        Get all module params in place them in a dictionary

        Returns:
            dict: dictionary of
        '''
        data = {}
        data['capabilities'] = self.module.params['capabilities']
        data['role_realtime_limit'] = self.module.params['role_realtime_limit']
        data['role_total_limit'] = self.module.params['role_total_limit']
        data['app'] = self.module.params['app']
        data['imported_roles'] = self.module.params['imported_roles']
        data['name'] = self.module.params['name']
        data['disk_quota'] = self.module.params['disk_quota']
        data['filter'] = self.module.params['filter']
        data['allowed_indexes'] = self.module.params['allowed_indexes']
        data['default_indexes'] = self.module.params['default_indexes']
        data['user_realtime_limit'] = self.module.params['user_realtime_limit']
        data['user_total_limit'] = self.module.params['user_total_limit']
        data['time_limit'] = self.module.params['time_limit']
        data['earliest_search'] = self.module.params['earliest_search']

        return data


def main():
    argument_spec = dict(
        capabilities=dict(
            type='list',
            elements='str'
        ),
        role_realtime_limit=dict(
            type='int'
        ),
        role_total_limit=dict(
            type='int'
        ),
        app=dict(
            type='str'
        ),
        imported_roles=dict(
            type='list',
            elements='str'
        ),
        name=dict(
            type='str',
            required=True
        ),
        disk_quota=dict(
            type='int'
        ),
        filter=dict(
            type='str'
        ),
        allowed_indexes=dict(
            type='list',
            elements='str'
        ),
        default_indexes=dict(
            type='list',
            elements='str'
        ),
        user_realtime_limit=dict(
            type='int'
        ),
        user_total_limit=dict(
            type='int'
        ),
        time_limit=dict(
            type='str'
        ),
        earliest_search=dict(
            type='str'
        ),
        state=dict(
            type='str',
            default='present',
            choices=['present', 'absent']
        )
    )

    argument_spec.update(SplunkHelpers.splunk_common_argument_spec())
    required_args = SplunkHelpers.splunk_common_required_one()
    exclusive_args = SplunkHelpers.splunk_common_mutual_exclusive()
    required_if = [
        ('state', 'present', ('imported_roles', 'capabilities'))
    ]
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=exclusive_args,
        required_one_of=required_args,
        required_if=required_if,
        supports_check_mode=False
    )

    role = SplunkRole(module)
    existing_role = role.role_exists(module.params['name'])
    state = module.params['state']

    if state == "absent":
        if existing_role:
            role.delete_role()
            module.exit_json(
                changed=True, result=f"Successfully deleted role {module.params['name']}")
        else:
            module.exit_json(
                stdout=f"Role {module.params['name']} not found, no change", changed=False)

    # Set value for earliest_search
    earliest_search = module.params['earliest_search']
    if earliest_search is None:
        earliest_search = -1
    elif earliest_search == "unlimited":
        earliest_search = 0
    elif earliest_search.isnumeric():
        earliest_search = int(earliest_search)
    else:
        module.fail_json(
            msg="'earliest_search' must be either an integer (in seconds), or 'unlimited")
    module.params['earliest_search'] = earliest_search

    # Set value for time_limit
    time_limit = module.params['time_limit']
    if time_limit is None:
        time_limit = -1
    elif time_limit == "unlimited":
        time_limit = 0
    elif time_limit.isnumeric():
        time_limit = int(time_limit)
    else:
        module.fail_json(
            msg="'time_limit' must be either an integer (in seconds), or 'unlimited")
    module.params['time_limit'] = time_limit

    # Validate search limits
    for i in ['user_total_limit', 'user_realtime_limit', 'role_total_limit', 'role_realtime_limit']:
        if module.params[i] < 0:
            module.fail_json(
                msg=f"The value of '{i}' must be either 0 (for unlimited) or a posative number.")

    # Validate Inherited Roles
    imported_roles = module.params['imported_roles']
    for trole in imported_roles:
        if not role.valid_role(trole):
            module.fail_json(
                msg=f"The '{trole}' role is not available for inheritance.")

    # Validate capabilities
    capabilities = module.params['capabilities']
    for capability in capabilities:
        if not role.valid_capability(capability):
            module.fail_json(
                msg=f"The '{capability}' capability is not available for assignment.")

    # Modify or Create Role
    if not existing_role:
        response = role.create_role()
        module.exit_json(
            changed=True, result=f"Successfully created role {module.params['name']}")
    else:
        role.modify_role(existing_role)


if __name__ == '__main__':
    main()
