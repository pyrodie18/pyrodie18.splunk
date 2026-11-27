# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.pyrodie18.splunk.plugins.module_utils.server_info import (
    read_server_info,
)
from ansible_collections.pyrodie18.splunk.plugins.plugin_utils.management_action import (
    ManagementAction,
)


class ActionModule(ManagementAction):
    def execute(self, client):
        return read_server_info(client)
