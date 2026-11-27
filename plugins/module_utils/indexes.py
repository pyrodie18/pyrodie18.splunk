# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and reconcile standalone Splunk indexes through the management API."""

import re

from ansible_collections.pyrodie18.splunk.plugins.module_utils.client import SplunkError

INDEXES_ENDPOINT = '/services/data/indexes'
CLUSTER_ENDPOINT = '/services/cluster/config'
MAX_INDEX_SETTING = 4294967295
INDEX_SETTINGS = {
    'retention_seconds': 'frozenTimePeriodInSecs',
    'max_total_size_mb': 'maxTotalDataSizeMB',
}
INDEX_INFO_ARGUMENT_SPEC = {'name': {'type': 'str'}}
INDEX_ARGUMENT_SPEC = {
    'name': {'type': 'str', 'required': True},
    **{key: {'type': 'int'} for key in INDEX_SETTINGS},
}


def _entries(document, endpoint):
    entries = document.get('entry') if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise SplunkError(f'{endpoint}: expected an entry list')
    return entries


def _normalize_index(entry, endpoint):
    name = entry.get('name') if isinstance(entry, dict) else None
    content = entry.get('content') if isinstance(entry, dict) else None
    if not isinstance(name, str) or not name or not isinstance(content, dict):
        raise SplunkError(f'{endpoint}: expected a named entry with a content object')
    datatype = content.get('datatype')
    if datatype not in ('event', 'metric'):
        raise SplunkError(f'{endpoint}: missing or invalid index datatype')

    index = {'name': name, 'datatype': datatype}
    for key, field in INDEX_SETTINGS.items():
        value = content.get(field)
        if isinstance(value, str) and re.fullmatch(r'[0-9]{1,10}', value):
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_INDEX_SETTING:
            raise SplunkError(f'{endpoint}: missing or invalid {field}')
        index[key] = value
    return index


def _index_endpoint(name):
    if not re.fullmatch(r'[a-z0-9_-]+', name) or name in ('_new', '_reload', '_acl'):
        raise SplunkError('name must be an index name using lowercase letters, digits, underscores, or hyphens')
    return f'{INDEXES_ENDPOINT}/{name}'


def read_indexes(client, name=None):
    """Return visible indexes, or an empty list for a missing named resource."""
    if name is None:
        entries = _entries(client.get_json(INDEXES_ENDPOINT, count=0, datatype='all'), INDEXES_ENDPOINT)
        return sorted(
            (_normalize_index(entry, INDEXES_ENDPOINT) for entry in entries),
            key=lambda index: index['name'],
        )

    endpoint = _index_endpoint(name)
    try:
        document = client.get_json(endpoint)
    except SplunkError as error:
        if error.status == 404:
            return []
        raise
    indexes = [_normalize_index(entry, endpoint) for entry in _entries(document, endpoint)]
    if len(indexes) != 1 or indexes[0]['name'] != name:
        raise SplunkError(f'{endpoint}: expected one matching index')
    return indexes


def _require_standalone(client):
    entries = _entries(client.get_json(CLUSTER_ENDPOINT), CLUSTER_ENDPOINT)
    # Splunk can return an empty feed when clustering has not been configured.
    for entry in entries:
        content = entry.get('content') if isinstance(entry, dict) else None
        if not isinstance(content, dict) or content.get('mode') != 'disabled':
            raise SplunkError('index requires a standalone instance with indexer clustering disabled')


def ensure_index(client, name, retention_seconds=None, max_total_size_mb=None, *, check_mode=False, diff=False):
    """Plan or apply creation and changes to explicitly supplied settings."""
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', name or '') or 'kvstore' in name:
        raise SplunkError('name must start with a lowercase letter or digit, use only lowercase letters, digits, underscores, or hyphens, and omit kvstore')
    desired = {
        key: value for key, value in (
            ('retention_seconds', retention_seconds),
            ('max_total_size_mb', max_total_size_mb),
        ) if value is not None
    }
    for key, value in desired.items():
        if not 0 <= value <= MAX_INDEX_SETTING:
            raise SplunkError(f'{key} must be between 0 and {MAX_INDEX_SETTING}')

    _require_standalone(client)
    before = next(iter(read_indexes(client, name)), None)
    if before is not None and before['datatype'] != 'event':
        raise SplunkError('index can only manage event indexes')

    updates = {key: value for key, value in desired.items() if before is None or before[key] != value}
    changed = before is None or bool(updates)
    after = dict(before or {'name': name, 'datatype': 'event'}, **updates)

    if changed and not check_mode:
        fields = {INDEX_SETTINGS[key]: value for key, value in updates.items()}
        if before is None:
            client.post_form(INDEXES_ENDPOINT, dict(fields, name=name, datatype='event'))
        else:
            client.post_form(_index_endpoint(name), fields)

        try:
            stored = next(iter(read_indexes(client, name)), None)
        except SplunkError as error:
            raise SplunkError(f'Splunk accepted the write, but verification failed. {error}', error.status, changed=True) from None
        if stored is None or stored['datatype'] != 'event' or any(stored[key] != value for key, value in desired.items()):
            raise SplunkError('Splunk accepted the write, but the stored index does not match the requested settings', changed=True)
        after = stored

    result = {'changed': changed, 'index': after}
    if changed and diff:
        result['diff'] = {'before': before or {}, 'after': after}
    return result
