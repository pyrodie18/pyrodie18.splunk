#!/usr/bin/python

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

DOCUMENTATION = r'''
---
module: server_info
short_description: Read Splunk Enterprise server identity and roles
version_added: "0.1.0"
description:
  - Read the identity and roles of a Splunk Enterprise server through its management API.
  - The credential must be allowed to read C(/services/server/info). If that response omits server roles,
    the credential must also be allowed to read C(/services/server/roles).
  - The action plugin contacts the management API from the controller or execution environment.
  - Set connection defaults in inventory as C(splunk_url), C(splunk_validate_certs), C(splunk_ca_path), and C(splunk_timeout).
  - Supply authentication as task arguments, in inventory, or through the corresponding C(SPLUNK_API_*) environment variables.
  - For inventory authentication use C(splunk_token) or the C(splunk_username) and C(splunk_password) pair.
author:
  - pyrodie18 (@pyrodie18)
options:
  url:
    description:
      - HTTPS origin of the Splunk management API, typically V(https://splunk.example.com:8089).
      - Required unless provided by C(splunk_url) in inventory.
    type: str
  token:
    description:
      - Splunk management API bearer token.
      - Supply this or the O(username) and O(password) pair.
    type: str
  username:
    description:
      - Username for HTTP Basic authentication.
      - Required with O(password) and mutually exclusive with O(token).
    type: str
  password:
    description:
      - Password for HTTP Basic authentication.
      - Required with O(username) and mutually exclusive with O(token).
    type: str
  validate_certs:
    description:
      - Verify the management server certificate and hostname.
      - Disable only for a disposable lab with an untrusted certificate.
    type: bool
    default: true
  ca_path:
    description:
      - Path on the execution host to a PEM CA file used to verify the server.
      - Used when O(validate_certs=true).
    type: path
  timeout:
    description:
      - Network timeout in seconds for each REST request. Must be at least one.
    type: int
    default: 10
attributes:
  action:
    description: A companion action plugin runs the REST requests on the controller.
    support: full
  connection:
    description: The action plugin performs REST requests independently of the host connection.
    support: none
  check_mode:
    description: Read server information without changing Splunk.
    support: full
  diff_mode:
    description: The module does not report diffs.
    support: none
'''

EXAMPLES = r'''
- name: Read Splunk identity using inventory connection settings
  pyrodie18.splunk.server_info:
  register: splunk_info
'''

RETURN = r'''
server_name:
  description: Splunk server name.
  returned: success
  type: str
  sample: splunk-dev-01
guid:
  description: Splunk server GUID.
  returned: success
  type: str
  sample: D4DBAE70-1C60-48F5-9A91-7222FDB7C528
version:
  description: Splunk Enterprise version.
  returned: success
  type: str
  sample: "10.2.2"
build:
  description: Splunk Enterprise build identifier.
  returned: success
  type: str
  sample: 80b90d638de6
roles:
  description: Sorted, unique Splunk server roles.
  returned: success
  type: list
  elements: str
  sample: [indexer, kv_store]
activeLicenseGroup:
  description: Active Splunk license group.
  returned: success when provided by Splunk
  type: str
  sample: "Trial"
cpu_arch:
  description: CPU architecture reported by Splunk.
  returned: success when provided by Splunk
  type: str
  sample: "x86_64"
host:
  description: Host name reported by Splunk.
  returned: success when provided by Splunk
  type: str
  sample: "splunk-dev-01"
host_fqdn:
  description: Fully qualified host name reported by Splunk.
  returned: success when provided by Splunk
  type: str
  sample: "splunk.example.com"
mode:
  description: Splunk instance operating mode.
  returned: success when provided by Splunk
  type: str
  sample: "normal"
numberOfCores:
  description: Number of processor cores.
  returned: success when provided by Splunk
  type: int
  sample: 4
os_build:
  description: Operating system build string.
  returned: success when provided by Splunk
  type: str
  sample: "Linux kernel build"
os_name:
  description: Operating system name.
  returned: success when provided by Splunk
  type: str
  sample: "Linux"
os_version:
  description: Operating system version reported by Splunk.
  returned: success when provided by Splunk
  type: str
  sample: "5.14.0"
physicalMemoryMB:
  description: Physical memory in megabytes.
  returned: success when provided by Splunk
  type: int
  sample: 7680
fips_mode:
  description: Whether Splunk is running in FIPS mode.
  returned: success when provided by Splunk
  type: bool
  sample: false
health_info:
  description: Splunk health status.
  returned: success when provided by Splunk
  type: str
  sample: "green"
numberOfVirtualCores:
  description: Number of virtual processor cores.
  returned: success when provided by Splunk
  type: int
  sample: 4
startup_time:
  description: Splunk process startup time as Unix epoch seconds.
  returned: success when provided by Splunk
  type: int
  sample: 1725871367
status:
  description: HTTP status code when the management API rejects the request.
  returned: when available on failure
  type: int
  sample: 403
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    SplunkClient,
    SplunkError,
)
from ansible_collections.pyrodie18.splunk.plugins.module_utils.server_info import (
    ARGUMENT_SPEC,
    AUTH_CONSTRAINTS,
    read_server_info,
)


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        **AUTH_CONSTRAINTS,
    )

    try:
        info = read_server_info(SplunkClient(**module.params))
    except SplunkError as exc:
        details = {'status': exc.status} if exc.status is not None else {}
        module.fail_json(msg=str(exc), exception=None, **details)
    module.exit_json(changed=False, **info)


if __name__ == '__main__':
    main()
