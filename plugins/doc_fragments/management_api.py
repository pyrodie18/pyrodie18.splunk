# SPDX-License-Identifier: GPL-3.0-or-later


class ModuleDocFragment:
    DOCUMENTATION = r"""
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
"""
