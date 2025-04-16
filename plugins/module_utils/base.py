from ansible.module_utils.urls import fetch_url
from ansible.module_utils.common.text.converters import to_native
import ansible_collections.pyrodie18.splunk.plugins.module_utils.helpers as SplunkHelpers
from ansible_collections.pyrodie18.splunk.plugins.module_utils.atom import AtomToDict
import http
import json
from urllib.parse import urlencode


class SplunkBase(object):
    """
    Base class for all modules
    """

    def __init__(self, module):
        self.module = module
        self.apps = None
        self.roles = None
        self.capabilities = None

    def payload_builder(self, params=None):
        if params is None:
            params = {}

        try:
            return json.dumps(params)
        except json.JSONEncoder:
            raise json.JSONEncoder(
                "Error serializing module parameters: %s" % params)

    def update_module(self, module):
        """
        Update the module within the object

        Args:
            module (module): The module to update
        """
        self.module = module

    def send_request(self, module, service_path, data=None, headers=None, method="GET", catch_404=False):
        """
        Sends a request via HTTP(S) to the Splunkd API interface

        Args:
            module (module): The AnsibleModule (urls class requires it but we feed the authentication info directly through the header)
            service_path (str): The path to the particular service being used
            data (json, optional): JSON encoded data to include in the API request. Defaults to None.
            headers (dict, optional): A dict with the request headers. Defaults to None.
            method (str, optional): HTTP method. Defaults to "GET".

        Raises:
            TypeError: _description_

        Returns:
            dict: HTTP response information
        """
        if headers is None:
            headers = {}

        # Extract login information
        splunk_api_username = module.params['splunk_api_username']
        splunk_api_password = module.params['splunk_api_password']
        splunk_api_auth_token = module.params['splunk_api_auth_token']
        splunk_api_uri = module.params['splunk_api_uri']
        splunk_api_port = module.params['splunk_api_port']

        # Build header and URL for request
        headers.update(SplunkHelpers.splunk_generate_auth_header(
            splunk_api_username, splunk_api_password, splunk_api_auth_token))
        full_url = f"{splunk_api_uri}:{splunk_api_port}/services{service_path}"

        # Format and encode data
        if data:
            data = urlencode(self._encode(**data))

        resp, info = fetch_url(module, full_url, data=data,
                               headers=headers, method=method,)

        # Decode HTTP response
        try:
            if resp.fp is None or resp.closed:
                raise TypeError
            content = AtomToDict(resp.read().decode('utf-8').strip())
        except (AttributeError, TypeError):
            content = info.pop('body', b'').decode('utf-8')
        except http.client.HTTPException as http_err:
            module.fail_json(
                msg=f"HTTP Error while fetching {full_url}: {to_native(http_err)}")

        response = {
            'status': resp.status,
            'reason': resp.reason,
            'headers': resp.getheaders(),
            'closed': resp.closed,
            'content': content
        }

        http_status = info['status']
        if http_status < 400:
            return response
        # Handle HTTP Errors
        elif http_status == 400:
            msg = f"An unexpected error occured while trying to connect to {full_url}:  {content}"
        elif http_status == 401:
            if splunk_api_username:
                msg = f"The specified splunk_api_username/password is invalid: {content}"
            else:
                msg = f"The specified splunk_api_token is invalid: {content}"
        elif http_status == 402:
            module.fail_json(
                msg=f"The currently installed Splunk license disables this feature: {content}")
        elif http_status == 403:
            if splunk_api_username:
                msg = f"The specified splunk_api_username does not have sufficient privlidges for this operation: {content}"
            else:
                msg = f"The specified splunk_api_token does not have sufficient privlidges for this operation: {content}"
        elif http_status == 404:
            if catch_404:
                return response
            else:
                msg = f"Error while attempting to connect to {full_url}: {content}"
        elif http_status == 409:
            msg = f"Invalid operation for endpoing {full_url}: {content}"
        elif http_status == 500:
            msg = f"An unexpected error occured while trying to connect to {full_url}:  {content}"
        elif http_status == 503:
            msg = f"The requested feature is disabled in the Splunk configuration {full_url}: {content}"
        module.fail_json(msg=msg)

    def valid_capability(self, capability):
        if self.capabilities is None:
            self._get_capabilities()

        return capability in self.capabilities

    def _get_capabilities(self):
        """
        Return a list of all possible capabilities that this version of Splunk supports.
        """
        search_path = "/authorization/capabilities"
        response = self.send_request(self.module, search_path)

        content = response["content"].parsed(key="feed.entry")[0]
        content = content['content']['capabilities']

        self.capabilities = content

    def get_app_name(self, app):
        if self.apps is None:
            self._get_apps()

        if app in self.apps.values():
            return app
        elif app in self.apps.keys():
            return self.apps[app]
        else:
            return None

    def _get_apps(self):
        search_path = "/apps/local"
        response = self.send_request(self.module, search_path)

        content = response["content"].parsed(key="feed.entry")
        apps = {}

        for app in content:
            app_label = app['content']['label']
            app_name = app['title']

            apps[app_label] = app_name

        self.apps = apps

    def valid_role(self, role):
        if self.roles is None:
            self._get_roles()

        return role in self.roles

    def _get_roles(self):
        """
        Retrieve a list of role names and set self.roles
        """
        search_path = "/authorization/roles"
        response = self.send_request(self.module, search_path)
        content = response["content"].parsed(key="feed.entry")

        roles = []

        for role in content:
            roles.append(role['title'])

        self.roles = roles

    def _encode(self, **kwargs):
        """
        Encode the given kwargs as a query string. This wrapper will also _encode
        a list value as a sequence of assignments to the corresponding arg name,
        for example an argument such as 'foo=[1,2,3]' will be encoded as
        'foo=1&foo=2&foo=3'.
        """
        items = []
        for key, value in kwargs.items():
            if isinstance(value, list):
                items.extend([(key, item) for item in value])
            else:
                items.append((key, value))

        return items
