#!/usr/bin/python

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r'''
---
module: index
short_description: Manage a standalone Splunk Enterprise event index
version_added: "0.1.0"
description:
  - Create a local event index or edit the specified settings on an existing event index.
  - The credential must be able to read C(/services/cluster/config) and read and write C(/services/data/indexes).
  - Uses the controller connection settings and credentials documented for M(pyrodie18.splunk.server_info).
  - Splunk can freeze and delete existing data when retention or size limits decrease. Review changes with C(--check --diff).
author:
  - pyrodie18 (@pyrodie18)
extends_documentation_fragment:
  - pyrodie18.splunk.management_api
options:
  name:
    description:
      - Name of the event index.
      - Use lowercase letters, digits, underscores, or hyphens. Start with a letter or digit. The name cannot contain V(kvstore).
    type: str
    required: true
  retention_seconds:
    description:
      - Age in seconds after which Splunk rolls indexed data to frozen.
      - Between zero and 4294967295. Omit to use Splunk's default on creation or preserve the current value on update.
    type: int
  max_total_size_mb:
    description:
      - Maximum total index size in megabytes.
      - Between zero and 4294967295. Omit to use Splunk's default on creation or preserve the current value on update.
    type: int
attributes:
  action:
    description: A companion action plugin runs the REST requests on the controller.
    support: full
  connection:
    description: The REST requests run independently of the Ansible host connection.
    support: none
  check_mode:
    description: Predicts index creation and setting changes without writing to Splunk.
    support: full
  diff_mode:
    description: Shows the previous and resulting settings for a change.
    support: full
'''

EXAMPLES = r'''
- name: Ensure the application event index exists
  pyrodie18.splunk.index:
    name: application_events
    retention_seconds: 2592000
    max_total_size_mb: 10000
'''

RETURN = r'''
index:
  description: Stored index settings, or predicted settings in check mode.
  returned: success
  type: dict
  contains:
    name:
      description: Index name.
      type: str
    datatype:
      description: Index type, always V(event).
      type: str
    retention_seconds:
      description: Age before data rolls to frozen. Omitted when unspecified in a check-mode creation.
      type: int
    max_total_size_mb:
      description: Maximum total size in megabytes. Omitted when unspecified in a check-mode creation.
      type: int
status:
  description: HTTP status code when the management API rejects the request.
  returned: when available on failure
  type: int
  sample: 403
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    CONNECTION_ARGUMENT_SPEC,
)
from ansible_collections.pyrodie18.splunk.plugins.module_utils.indexes import (
    INDEX_ARGUMENT_SPEC,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(CONNECTION_ARGUMENT_SPEC, **INDEX_ARGUMENT_SPEC),
        supports_check_mode=True,
    )
    module.fail_json(msg='This module requires its controller-side action plugin')


if __name__ == '__main__':
    main()
