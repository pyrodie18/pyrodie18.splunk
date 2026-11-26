#!/usr/bin/python
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r'''
---
module: service_info
short_description: Read Splunk Enterprise CLI version and service status
version_added: "0.1.0"
description:
  - Run the read-only Splunk version and status commands on the inventory host.
  - Use Ansible's standard host connection and privilege escalation settings to run as the Splunk service account.
author:
  - pyrodie18 (@pyrodie18)
options:
  splunk_home:
    description:
      - Splunk installation directory on the target host.
      - Defaults to the C(splunk_home) inventory variable when set.
    type: path
    default: /opt/splunk
attributes:
  action:
    description: A companion action plugin supplies the inventory default.
    support: full
  check_mode:
    description: Read the service status without changing Splunk.
    support: full
'''

EXAMPLES = r'''
- name: Check the Splunk service using the inventory connection
  pyrodie18.splunk.service_info:
  register: splunk_service
'''

RETURN = r'''
version:
  description: Version and build text reported by the Splunk CLI.
  returned: success
  type: str
  sample: Splunk 10.2.2 (build 80b90d638de6)
status:
  description: Service status text reported by the Splunk CLI.
  returned: success
  type: str
  sample: splunkd is running (PID 6565).
'''

import os

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec={'splunk_home': {'type': 'path', 'default': '/opt/splunk'}},
        supports_check_mode=True,
    )
    binary = os.path.join(module.params['splunk_home'], 'bin', 'splunk')
    output = {}
    for command in ('version', 'status'):
        rc, stdout, _stderr = module.run_command([binary, command, '--no-prompt'], expand_user_and_vars=False)
        if rc:
            module.fail_json(msg=f'splunk {command} failed (exit {rc})', rc=rc, changed=False)
        output[command] = stdout.strip()
    module.exit_json(changed=False, **output)


if __name__ == '__main__':
    main()
