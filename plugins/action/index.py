# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.pyrodie18.splunk.plugins.module_utils.indexes import (
    INDEX_ARGUMENT_SPEC,
    ensure_index,
)
from ansible_collections.pyrodie18.splunk.plugins.plugin_utils.management_action import (
    ManagementAction,
)


class ActionModule(ManagementAction):
    argument_spec = INDEX_ARGUMENT_SPEC

    def execute(self, client, **params):
        return ensure_index(client, check_mode=self._task.check_mode, diff=self._task.diff, **params)
