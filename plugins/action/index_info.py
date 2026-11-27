# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.pyrodie18.splunk.plugins.module_utils.indexes import (
    INDEX_INFO_ARGUMENT_SPEC,
    read_indexes,
)
from ansible_collections.pyrodie18.splunk.plugins.plugin_utils.management_action import (
    ManagementAction,
)


class ActionModule(ManagementAction):
    argument_spec = INDEX_INFO_ARGUMENT_SPEC

    def execute(self, client, **params):
        return {'indexes': read_indexes(client, **params)}
