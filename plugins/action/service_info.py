# SPDX-License-Identifier: GPL-3.0-or-later

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        host = task_vars['hostvars'][task_vars['inventory_hostname']]
        arguments = self._task.args.copy()
        if 'splunk_home' not in arguments and 'splunk_home' in host:
            arguments['splunk_home'] = host['splunk_home']
        try:
            result.update(self._execute_module(module_args=arguments, task_vars=task_vars))
        finally:
            self._remove_tmp_path(self._connection._shell.tmpdir)
        return result
