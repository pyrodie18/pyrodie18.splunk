# SPDX-License-Identifier: GPL-3.0-or-later

import os

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.parameters import remove_values
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    SplunkClient,
    SplunkError,
)
from ansible_collections.pyrodie18.splunk.plugins.module_utils.server_info import (
    ARGUMENT_SPEC,
    AUTH_CONSTRAINTS,
    read_server_info,
)

AUTH_ENV = {
    'token': 'SPLUNK_API_TOKEN',
    'username': 'SPLUNK_API_USERNAME',
    'password': 'SPLUNK_API_PASSWORD',
}
display = Display()


class ActionModule(ActionBase):
    _requires_connection = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        host = task_vars['hostvars'][task_vars['inventory_hostname']]
        arguments = self._task.args.copy()
        for option in ('url', 'validate_certs', 'ca_path', 'timeout'):
            variable = f'splunk_{option}'
            if option not in arguments and variable in host:
                arguments[option] = host[variable]

        if not any(option in arguments for option in AUTH_ENV):
            inventory_auth = {
                option: host[f'splunk_{option}'] for option in AUTH_ENV if f'splunk_{option}' in host
            }
            arguments.update(inventory_auth or {
                option: os.environ[variable] for option, variable in AUTH_ENV.items() if os.environ.get(variable)
            })

        secrets = {
            value for key in ('url', 'token', 'password')
            if isinstance(value := arguments.get(key), str) and value
        }
        validation = ArgumentSpecValidator(ARGUMENT_SPEC, **AUTH_CONSTRAINTS).validate(arguments)
        if validation.error_messages:
            return dict(result, failed=True, msg=remove_values(validation.error_messages[0], secrets))

        display.vvv('Using the Splunk management API from the controller', host=task_vars['inventory_hostname'])
        try:
            result.update(read_server_info(SplunkClient(**validation.validated_parameters)))
        except SplunkError as error:
            result.update(failed=True, msg=str(error))
            if error.status is not None:
                result['status'] = error.status
        result['changed'] = False
        return remove_values(result, secrets)
