# SPDX-License-Identifier: GPL-3.0-or-later

"""Argument schema and shared read behavior for Splunk server discovery."""

from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    SplunkError,
    single_entry_content,
)

ARGUMENT_SPEC = {
    'url': {'type': 'str', 'no_log': True},
    'token': {'type': 'str', 'no_log': True},
    'username': {'type': 'str'},
    'password': {'type': 'str', 'no_log': True},
    'validate_certs': {'type': 'bool', 'default': True},
    'ca_path': {'type': 'path'},
    'timeout': {'type': 'int', 'default': 10},
}
AUTH_CONSTRAINTS = {
    'required_one_of': [('token', 'username')],
    'required_together': [('username', 'password')],
    'mutually_exclusive': [('token', 'username')],
}

INFO_ENDPOINT = '/services/server/info'
ROLES_ENDPOINT = '/services/server/roles'
ADDITIONAL_INFO_FIELDS = (
    'activeLicenseGroup',
    'cpu_arch',
    'host',
    'host_fqdn',
    'mode',
    'numberOfCores',
    'os_build',
    'os_name',
    'os_version',
    'physicalMemoryMB',
    'fips_mode',
    'health_info',
    'numberOfVirtualCores',
    'startup_time',
)


def read_server_info(client):
    info = single_entry_content(client.get_json(INFO_ENDPOINT), INFO_ENDPOINT)
    identity = {
        'server_name': info.get('serverName'),
        'guid': info.get('guid'),
        'version': info.get('version'),
        'build': info.get('build'),
    }
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise SplunkError(f'{INFO_ENDPOINT}: missing or invalid server identity fields')

    role_source = INFO_ENDPOINT
    if 'server_roles' in info:
        roles = info['server_roles']
    else:
        role_source = ROLES_ENDPOINT
        roles = single_entry_content(client.get_json(role_source), role_source).get('role_list')
    if not isinstance(roles, list) or any(not isinstance(role, str) or not role for role in roles):
        raise SplunkError(f'{role_source}: expected a list of role names')
    identity.update({field: info[field] for field in ADDITIONAL_INFO_FIELDS if field in info})
    return dict(identity, roles=sorted(set(roles)))
