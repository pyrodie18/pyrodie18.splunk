# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared transport for Splunk Enterprise management API requests."""

import json
import ssl
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit

from ansible.module_utils.urls import basic_auth_header, open_url

CONNECTION_ARGUMENT_SPEC = {
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


class SplunkError(Exception):
    """A sanitized error suitable for reporting in an Ansible result."""

    def __init__(self, message, status=None, changed=False):
        super().__init__(message)
        self.status = status
        self.changed = changed


def management_origin(url):
    """Validate an HTTPS origin without exposing user-supplied URL text."""
    message = 'url must be an HTTPS origin without credentials, a path, a query, or a fragment'
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise SplunkError(message) from None

    if (
        parsed.scheme != 'https'
        or not parsed.hostname
        or parsed.username is not None
        or parsed.path not in ('', '/')
        or port == 0
        or parsed.netloc.endswith(':')
        or any(character.isspace() or character in '?#\\' for character in url)
    ):
        raise SplunkError(message)
    return 'https://' + parsed.netloc


class SplunkClient:
    """Make authenticated, direct requests to a single Splunk origin."""

    def __init__(self, url, token, username, password, validate_certs, ca_path, timeout):
        self.origin = management_origin(url)
        if timeout < 1:
            raise SplunkError('timeout must be at least 1 second')

        self.options = {
            'timeout': timeout,
            'validate_certs': validate_certs,
            'ca_path': ca_path if validate_certs else None,
        }
        if token is not None:
            if not token or any(character.isspace() for character in token):
                raise SplunkError('token must be nonempty and contain no whitespace')
            authorization = 'Bearer ' + token
        else:
            if not username or ':' in username or not password:
                raise SplunkError('Basic authentication requires a nonempty username without colons and a nonempty password')
            authorization = basic_auth_header(username, password).decode('ascii')
        self.headers = {'Accept': 'application/json', 'Authorization': authorization}

    def get_json(self, endpoint, **query):
        """Retrieve a JSON document."""
        return self._request(endpoint, query=query)

    def post_form(self, endpoint, fields):
        """Submit a form. The caller can read the resource to verify stored values."""
        self._request(endpoint, data=urlencode(fields).encode('ascii'))

    def _request(self, endpoint, query=None, data=None):
        params = urlencode(dict(query or {}, output_mode='json'))
        headers = self.headers
        if data is not None:
            headers = {**headers, 'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            with open_url(
                self.origin + endpoint + '?' + params,
                data=data,
                method='GET' if data is None else 'POST',
                headers=headers,
                follow_redirects='none',
                use_netrc=False,
                use_proxy=False,
                **self.options,
            ) as response:
                if data is None:
                    return json.load(response)
        except HTTPError as exc:
            with exc:
                status = exc.code
            if 300 <= status < 400:
                reason = 'redirect rejected'
            elif status == 401:
                reason = 'authentication failed'
            elif status == 403:
                reason = 'permission denied'
            else:
                reason = 'request failed'
            raise SplunkError(f'{endpoint}: {reason} (HTTP {status})', status) from None
        except (URLError, OSError) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(reason, (ssl.SSLError, FileNotFoundError)):
                message = 'TLS verification or certificate setup failed'
            elif isinstance(reason, TimeoutError):
                message = 'request timed out'
            else:
                message = 'connection failed'
            raise SplunkError(f'{endpoint}: {message}') from None
        except HTTPException:
            raise SplunkError(f'{endpoint}: invalid HTTP response') from None
        except (TypeError, ValueError):
            raise SplunkError(f'{endpoint}: invalid JSON response or request header') from None


def single_entry_content(document, endpoint):
    """Read the content of a singleton Splunk REST resource."""
    entries = document.get('entry') if isinstance(document, dict) else None
    if isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict):
        content = entries[0].get('content')
        if isinstance(content, dict):
            return content
    raise SplunkError(f'{endpoint}: expected one entry with a content object')
