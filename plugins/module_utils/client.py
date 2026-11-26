# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared transport for Splunk Enterprise management API requests."""

import json
import ssl
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from ansible.module_utils.urls import basic_auth_header, open_url


class SplunkError(Exception):
    """A sanitized error suitable for reporting in an Ansible result."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


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

    def get_json(self, endpoint):
        """Retrieve a JSON document and discard untrusted error details."""
        try:
            with open_url(
                self.origin + endpoint + '?output_mode=json',
                method='GET',
                headers=self.headers,
                follow_redirects='none',
                use_netrc=False,
                use_proxy=False,
                **self.options,
            ) as response:
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
