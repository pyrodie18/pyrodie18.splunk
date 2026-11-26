from unittest.mock import Mock

import pytest
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    SplunkError,
    management_origin,
)
from ansible_collections.pyrodie18.splunk.plugins.module_utils.server_info import (
    INFO_ENDPOINT,
    ROLES_ENDPOINT,
    read_server_info,
)


@pytest.mark.parametrize('url', [
    'http://splunk.example.com:8089',
    'https://name:password@splunk.example.com',
    'https://splunk.example.com/services',
    'https://splunk.example.com/?',
    'https://splunk.example.com/#',
    'https://splunk.example.com:0',
    'https://splunk.example.com:wrong',
])
def test_reject_invalid_origins(url):
    with pytest.raises(SplunkError, match='must be an HTTPS origin') as error:
        management_origin(url)
    assert url not in str(error.value)


def test_accept_ipv6_origin_with_trailing_slash():
    assert management_origin('https://[2001:db8::1]:8089/') == 'https://[2001:db8::1]:8089'


@pytest.mark.parametrize('additional_info', [
    {},
    {
        'activeLicenseGroup': 'Trial',
        'cpu_arch': 'x86_64',
        'host': 'splunk-fixture',
        'host_fqdn': 'splunk.example.com',
        'mode': 'normal',
        'numberOfCores': 4,
        'os_build': 'Linux kernel build',
        'os_name': 'Linux',
        'os_version': '5.14.0',
        'physicalMemoryMB': 7680,
        'fips_mode': False,
        'health_info': 'green',
        'numberOfVirtualCores': 4,
        'startup_time': 1725871367,
    },
])
def test_allowlist_identity_and_normalize_roles(additional_info):
    client = Mock()
    client.get_json.side_effect = [
        {'entry': [{'content': {
            'serverName': 'splunk-fixture',
            'guid': 'fixture-guid',
            'version': '10.2.2',
            'build': 'test-build',
            'licenseKeys': ['private-license'],
            **additional_info,
        }}]},
        {'entry': [{'content': {'role_list': ['kv_store', 'indexer', 'indexer', 'new_role']}}]},
    ]
    assert read_server_info(client) == {
        'server_name': 'splunk-fixture',
        'guid': 'fixture-guid',
        'version': '10.2.2',
        'build': 'test-build',
        'roles': ['indexer', 'kv_store', 'new_role'],
        **additional_info,
    }
    assert [call.args[0] for call in client.get_json.call_args_list] == [INFO_ENDPOINT, ROLES_ENDPOINT]


@pytest.mark.parametrize('document', [None, {}, {'entry': []}, {'entry': [{'content': []}]}])
def test_fail_on_invalid_entry(document):
    client = Mock()
    client.get_json.return_value = document
    with pytest.raises(SplunkError, match='expected one entry'):
        read_server_info(client)


def test_fail_on_wrong_role_type():
    client = Mock()
    client.get_json.side_effect = [
        {'entry': [{'content': {
            'serverName': 'splunk-fixture', 'guid': 'id', 'version': '10.2.2', 'build': 'test-build',
        }}]},
        {'entry': [{'content': {'role_list': [True]}}]},
    ]
    with pytest.raises(SplunkError, match='expected a list of role names'):
        read_server_info(client)
