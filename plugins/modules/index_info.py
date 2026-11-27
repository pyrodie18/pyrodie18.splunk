#!/usr/bin/python

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r'''
---
module: index_info
short_description: Read Splunk Enterprise indexes
version_added: "0.1.0"
description:
  - List event and metrics indexes visible to the supplied credential, or look up a single index by name.
  - Uses the controller connection settings and credentials documented for M(pyrodie18.splunk.server_info).
author:
  - pyrodie18 (@pyrodie18)
extends_documentation_fragment:
  - pyrodie18.splunk.management_api
options:
  name:
    description:
      - Index name to look up.
      - A missing index returns an empty list.
    type: str
attributes:
  action:
    description: A companion action plugin runs the REST requests on the controller.
    support: full
  connection:
    description: The REST requests run independently of the Ansible host connection.
    support: none
  check_mode:
    description: Read index settings without changing Splunk.
    support: full
  diff_mode:
    description: The module does not report diffs.
    support: none
'''

EXAMPLES = r'''
- name: List indexes visible to the management credential
  pyrodie18.splunk.index_info:
  register: splunk_indexes

- name: Look up the application index
  pyrodie18.splunk.index_info:
    name: application_events
  register: application_index
'''

RETURN = r'''
indexes:
  description: Visible indexes sorted by name, or a list with the matching index when a name is supplied.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: Index name.
      type: str
    datatype:
      description: Index type, V(event) or V(metric).
      type: str
    retention_seconds:
      description: Age in seconds at which indexed data rolls to frozen.
      type: int
    max_total_size_mb:
      description: Maximum total index size in megabytes.
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
    INDEX_INFO_ARGUMENT_SPEC,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(CONNECTION_ARGUMENT_SPEC, **INDEX_INFO_ARGUMENT_SPEC),
        supports_check_mode=True,
    )
    module.fail_json(msg='This module requires its controller-side action plugin')


if __name__ == '__main__':
    main()
