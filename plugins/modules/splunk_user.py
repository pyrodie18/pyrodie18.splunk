#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Troy Ward
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: splunk_user
short_description: Create/update/delete Splunk users
description:
    - Create/update/delete Splunk users.
author:
    - "Troy Ward (@pyrodie18)"
requirements:
    - "python >= 3.11"
version_added: '1.0.0'
options:
    name:
        description:
            - The name of the user being created/modified/deleted
        required: true
        type: str
    state:
        description:
            - V(present) - create/update user.
            - V(absent) - delete user.
        choices: [present, absent]
        default: "present"
        type: str
    app:
        description:
            - The default app for the user.
        default: "launcher"
        type: str
    create_role:
        description:
            - Have Splunk create a unique role for the user
            - If O(state=present) this must be set or O(roles) must have a value.
        type: bool
        default: false
    email:
        description:
            - The users email address.
        type: str
    force_password_change:
        description:
            - Force the user to change their password on next login.
        type: bool
        default: true
    full_name:
        description:
            - The users first and last name.
        type: str
    password:
        description:
            - The password for the user.
            - This B(CAN NOT) be used to change a users password after initial creation.
            - This must be set if O(state=present).
        type: str
    roles:
        description:
            - A list of role names to attach to the user.
        type: list
        elements: str
        default: ["user"]
    time_zone:
        description:
            - The user's timezone.
        type: str

extends_documentation_fragment:
    - pyrodie18.splunk.splunk

"""

EXAMPLES = """
---
# Create a new user
- name: Create test_user
  pyrodie18.splunk.splunk_user:
    name: test_user
    password: 'PASSword123!@#'
    state: present
    roles:
        - user
        - admin
    splunk_api_user: admin
    splunk_api_password: 'PASSword123!@#'
    splunk_api_uri: https://localhost

# Delete user
- name: Delete test_user
  pyrodie18.splunk.splunk_user:
    name: test_user
    state: absent

"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.pyrodie18.splunk.plugins.module_utils.helpers as SplunkHelpers
from ansible_collections.pyrodie18.splunk.plugins.module_utils.base import SplunkBase


class SplunkUser(SplunkBase):
    SERVICE_PATH = "/authentication/users"
    FIELD_MAPPING = {
        "app": "defaultApp",
        "create_role": "createrole",
        "force_password_change": "force-change-pass",
        "full_name": "realname",
        "time_zone": "tz"
    }

    def __init__(self, module):
        super().__init__(module)
        self.username = self.module.params['name']

    def user_exists(self, username=None):
        """
        Checks to see if the specified user already exists

        return:  The user information if found or False if not found
        """
        if not username:
            username = self.module.parms['name']
        search_path = f"{self.SERVICE_PATH}/{username}"
        response = self.send_request(self.module, search_path, catch_404=True)

        if response['status'] == 404:
            return False

        content = response["content"].parsed(key="feed.entry")[0]
        mod_resp = self._build_response(content)
        return mod_resp

    def delete_user(self):
        """
        Deletes the user specified in the module
        """
        service_path = f"{self.SERVICE_PATH}/{self.username}"
        response = self.send_request(
            self.module, service_path, method="DELETE")

    def create_user(self):
        input_data = self._build_input()
        input_data = SplunkHelpers.splunk_sanatize_dict(input_data)
        input_data = SplunkHelpers.splunk_map_fields(
            input_data, self.FIELD_MAPPING)

        response = self.send_request(
            self.module, self.SERVICE_PATH, input_data, method="POST")
        content = response["content"].parsed(key="feed.entry")[0]
        mod_resp = self._build_response(content)
        return mod_resp

    def modify_user(self, current_state):
        desired_state = self._build_input()

        # If we are supposed to be creating a role, make sure its there and we're assigned to it
        if self.module.params['create_role']:
            self.module.params['roles'].append(f"user-{self.username}")

        # Cleanup fields that breack sameness check and compare
        desired_state = SplunkHelpers.splunk_sanatize_dict(
            desired_state, ['password', 'force_password_change'])
        current_state = SplunkHelpers.splunk_sanatize_dict(
            current_state, ['capabilities', 'user_locked_out', ])
        if SplunkHelpers.splunk_dict_is_same(desired_state, current_state):
            self.module.exit_json(
                stdout="User present, no change required", changed=False)

        # Regenerate endstate so I have the password to include
        # Related to Splunk Idea https://ideas.splunk.com/ideas/EID-I-2531
        desired_state = self._build_input()
        desired_state = SplunkHelpers.splunk_sanatize_dict(
            desired_state, ['name', 'create_role'])
        desired_state = SplunkHelpers.splunk_map_fields(
            desired_state, self.FIELD_MAPPING)

        service_path = f"{self.SERVICE_PATH}/{self.username}"
        response = self.send_request(
            self.module, service_path, desired_state, method="POST")
        self.module.exit_json(
            stdout=f"User {self.username}, configuration updated", changed=True)

    def _build_response(self, contents):
        """
        Build response dictionary

        Args:
            contents (dict): Dictionary containing all return values from query

        Returns:
            dict: Response information
        """
        response = {}
        response['name'] = SplunkHelpers.splunk_extract_value(
            contents, "title", None)
        response['capabilities'] = SplunkHelpers.splunk_extract_value(
            contents, "content.capabilities", None)
        response['app'] = SplunkHelpers.splunk_extract_value(
            contents, "content.defaultApp", None)
        response['email'] = SplunkHelpers.splunk_extract_value(
            contents, "content.email", None)
        response['user_locked_out'] = SplunkHelpers.splunk_extract_value(
            contents, "content.locked-out", None)
        response['capabilities'] = SplunkHelpers.splunk_extract_value(
            contents, "content.capabilities", None)
        response['full_name'] = SplunkHelpers.splunk_extract_value(
            contents, "content.realname", None)
        response['timezone'] = SplunkHelpers.splunk_extract_value(
            contents, "content.tz", None)
        response['roles'] = SplunkHelpers.splunk_extract_value(
            contents, "content.roles", None)

        return response

    def _build_input(self):
        """
        Get all module params in place them in a dictionary

        Returns:
            dict: dictionary of
        """
        data = {}
        data['app'] = self.module.params['app']
        data['create_role'] = self.module.params['create_role']
        data['email'] = self.module.params['email']
        data['force_password_change'] = self.module.params['force_password_change']
        data['full_name'] = self.module.params['full_name']
        data['name'] = self.module.params['name']
        data['password'] = self.module.params['password']
        data['roles'] = self.module.params['roles']
        data['time_zone'] = self.module.params['time_zone']

        return data


def main():
    argument_spec = dict(
        app=dict(
            type='str',
            default='launcher'
        ),
        create_role=dict(
            type='bool',
            default=False
        ),
        email=dict(
            type='str'
        ),
        force_password_change=dict(
            type='bool',
            default=True
        ),
        full_name=dict(
            type='str',
            required=False
        ),
        name=dict(
            type='str',
            required=True
        ),
        password=dict(
            type='str',
            no_log=True
        ),
        roles=dict(
            type='list',
            default=["user"],
            elements='str'
        ),
        state=dict(
            type='str',
            default='present',
            choices=['present', 'absent']
        ),
        time_zone=dict(
            type='str'
        ),
    )

    argument_spec.update(SplunkHelpers.splunk_common_argument_spec())
    required_args = SplunkHelpers.splunk_common_required_one()
    exclusive_args = SplunkHelpers.splunk_common_mutual_exclusive()
    required_if = [
        ('create_role', False, ('roles',)),
        ('state', 'present', ('password', 'app'))
    ]
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=exclusive_args,
        required_one_of=required_args,
        required_if=required_if,
        supports_check_mode=False
    )

    user = SplunkUser(module)
    existing_user = user.user_exists(module.params['name'])
    state = module.params['state']
    if state == "present":
        # Ensure that we are creating a role or have at least one defined
        create_role = module.params['create_role']
        roles = module.params['roles']
        if not create_role and len(roles) < 1:
            module.fail_json(
                msg="Either 'create_role' must me true or one or more roles must be listed in 'roles'")

    if state == "absent":
        if existing_user:
            user.delete_user()
            module.exit_json(
                changed=True, result=f"Successfully deleted user {module.params['name']}")
        else:
            module.exit_json(
                stdout=f"User {module.params['name']} not found, no change", changed=False)
    else:
        if not existing_user:
            response = user.create_user()
            module.exit_json(
                changed=True, result=f"Successfully created user {module.params['name']}")
        else:
            user.modify_user(existing_user)


if __name__ == '__main__':
    main()
