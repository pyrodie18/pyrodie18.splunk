# SPDX-License-Identifier: GPL-3.0-or-later

from unittest.mock import Mock

import pytest
from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import (
    SplunkError,
)
from ansible_collections.pyrodie18.splunk.plugins.module_utils.indexes import (
    CLUSTER_ENDPOINT,
    INDEXES_ENDPOINT,
    ensure_index,
    read_indexes,
)

NAME = 'test_events'
INDEX_ENDPOINT = f'{INDEXES_ENDPOINT}/{NAME}'


def index_document(datatype='event', retention=86400, size=500):
    return {'entry': [{'name': NAME, 'content': {
        'datatype': datatype,
        'frozenTimePeriodInSecs': retention,
        'maxTotalDataSizeMB': size,
    }}]}


def test_create_with_server_defaults():
    client = Mock()
    client.get_json.side_effect = [
        {'entry': []},
        SplunkError('not found', 404),
        index_document(retention='188697600', size='500000'),
    ]

    result = ensure_index(client, NAME)

    client.post_form.assert_called_once_with(INDEXES_ENDPOINT, {'name': NAME, 'datatype': 'event'})
    assert result == {'changed': True, 'index': {
        'name': NAME, 'datatype': 'event', 'retention_seconds': 188697600, 'max_total_size_mb': 500000,
    }}


def test_clustered_node_is_rejected_before_index_access():
    client = Mock()
    client.get_json.return_value = {'entry': [{'content': {'mode': 'peer'}}]}

    with pytest.raises(SplunkError, match='requires a standalone instance'):
        ensure_index(client, NAME)

    client.get_json.assert_called_once_with(CLUSTER_ENDPOINT)
    client.post_form.assert_not_called()


def test_metric_index_is_never_updated():
    client = Mock()
    client.get_json.side_effect = [{'entry': []}, index_document(datatype='metric')]

    with pytest.raises(SplunkError, match='only manage event indexes'):
        ensure_index(client, NAME, retention_seconds=100)

    client.post_form.assert_not_called()


@pytest.mark.parametrize('value', [True, 1.5, '-1', 'invalid'])
def test_malformed_retention_is_rejected(value):
    client = Mock()
    client.get_json.return_value = index_document(retention=value)

    with pytest.raises(SplunkError, match='missing or invalid frozenTimePeriodInSecs'):
        read_indexes(client, NAME)


def test_post_with_unverified_settings_reports_a_change_and_failure():
    client = Mock()
    client.get_json.side_effect = [{'entry': []}, index_document(), index_document()]

    with pytest.raises(SplunkError, match='stored index does not match') as raised:
        ensure_index(client, NAME, retention_seconds=100)

    assert raised.value.changed is True
    client.post_form.assert_called_once_with(INDEX_ENDPOINT, {'frozenTimePeriodInSecs': 100})
