# SPDX-License-Identifier: GPL-3.0-or-later

import os

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.parameters import remove_values
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    AUTH_CONSTRAINTS,
    CONNECTION_ARGUMENT_SPEC,
    SplunkClient,
    SplunkError,
)

AUTH_ENV = {
    'token': 'SPLUNK_API_TOKEN',
    'username': 'SPLUNK_API_USERNAME',
    'password': 'SPLUNK_API_PASSWORD',
}
display = Display()


class ManagementAction(ActionBase):
    _requires_connection = False
    _supports_check_mode = True
    argument_spec = {}

    def execute(self, client, **params):
        """Run the module operation from the controller."""
        raise NotImplementedError

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        result['changed'] = False
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
        validation = ArgumentSpecValidator(
            dict(CONNECTION_ARGUMENT_SPEC, **self.argument_spec), **AUTH_CONSTRAINTS
        ).validate(arguments)
        if validation.error_messages:
            return dict(result, failed=True, msg=remove_values(validation.error_messages[0], secrets))

        display.vvv('Using the Splunk management API from the controller', host=task_vars['inventory_hostname'])
        try:
            params = validation.validated_parameters
            client = SplunkClient(**{key: params[key] for key in CONNECTION_ARGUMENT_SPEC})
            result.update(self.execute(client, **{key: params[key] for key in self.argument_spec}))
        except SplunkError as error:
            result.update(failed=True, changed=error.changed, msg=str(error))
            if error.status is not None:
                result['status'] = error.status
        return remove_values(result, secrets)
