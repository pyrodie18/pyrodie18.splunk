"""Serve a temporary Splunk-like HTTPS API while Ansible runs the integration play."""

import json
import os
import ssl
import subprocess
import sys
from base64 import b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from time import sleep

TOKEN = 'fixture-valid-token'
PASSWORD = 'fixture-valid-password'
ERROR_BODY = b'fixture-private-error'
INFO_PATH = '/services/server/info?output_mode=json'
ROLES_PATH = '/services/server/roles?output_mode=json'


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, code, body, headers=None):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            # A request that exercised the client timeout can already be closed.
            pass

    def do_GET(self):
        authorization = self.headers.get('Authorization')
        if self.path == '/redirect-target':
            self.server.followed_redirect = True
            self.respond(200, b'{}')
            return
        if authorization == 'Bearer fixture-redirect-token':
            self.respond(302, ERROR_BODY, {'Location': '/redirect-target'})
            return
        if authorization == 'Bearer fixture-forbidden-token' and self.path == ROLES_PATH:
            self.respond(403, ERROR_BODY)
            return
        if authorization == 'Bearer fixture-malformed-token':
            self.respond(200, b'{fixture-private-error')
            return
        if authorization == 'Bearer fixture-timeout-token':
            sleep(2)
        elif authorization not in (
            'Bearer ' + TOKEN,
            'Basic ' + b64encode(f'fixture:{PASSWORD}'.encode()).decode(),
            'Bearer fixture-forbidden-token',
        ):
            self.respond(401, ERROR_BODY)
            return

        if self.path == INFO_PATH:
            content = {
                'serverName': 'splunk-fixture',
                'guid': 'fixture-guid',
                'version': '10.2.2',
                'build': 'fixture-build',
            }
        elif self.path == ROLES_PATH:
            content = {'role_list': ['kv_store', 'indexer', 'indexer']}
        else:
            self.respond(404, ERROR_BODY)
            return
        self.respond(200, json.dumps({'entry': [{'content': content}]}).encode())


def create_tls_context(directory):
    openssl_commands = [
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=Splunk test CA', '-keyout', 'ca.key', '-out', 'ca.pem'],
        ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=splunk-fixture',
         '-keyout', 'server.key', '-out', 'server.csr'],
        ['x509', '-req', '-days', '1', '-in', 'server.csr', '-CA', 'ca.pem',
         '-CAkey', 'ca.key', '-CAcreateserial', '-extfile', 'extensions', '-out', 'server.pem'],
    ]
    (directory / 'extensions').write_text('subjectAltName=IP:127.0.0.1\n')
    for arguments in openssl_commands:
        subprocess.run(['openssl', *arguments], cwd=directory, check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / 'server.pem', directory / 'server.key')
    return context


def main():
    with TemporaryDirectory() as path, ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler) as server:
        directory = Path(path)
        server.followed_redirect = False
        context = create_tls_context(directory)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            binary = directory / 'splunk' / 'bin' / 'splunk'
            binary.parent.mkdir(parents=True)
            binary.write_text(
                '#!/bin/sh\ncase "$1" in\n'
                '  version) echo "Splunk 10.2.2 (build fixture-build)" ;;\n'
                '  status) echo "splunkd is running (PID 42)." ;;\n'
                '  *) exit 1 ;;\nesac\n'
            )
            binary.chmod(0o700)
            variables = {
                'fixture_url': f'https://127.0.0.1:{server.server_port}',
                'fixture_ca': str(directory / 'ca.pem'),
                'fixture_token': TOKEN,
                'fixture_password': PASSWORD,
                'fixture_splunk_home': str(binary.parent.parent),
            }
            variables_file = directory / 'variables.json'
            variables_file.write_text(json.dumps(variables))
            result = subprocess.run(
                ['ansible-playbook', *sys.argv[1:], '-i', 'inventory.yml', '-vvv',
                 '-e', f'@{variables_file}', 'test.yml'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                env={
                    **os.environ,
                    'ANSIBLE_LOCAL_TEMP': str(directory),
                    'ANSIBLE_REMOTE_TEMP': str(directory),
                },
            )
        finally:
            server.shutdown()
            thread.join()

    secrets = (TOKEN.encode(), PASSWORD.encode(), ERROR_BODY, *(
        f'fixture-{scenario}-token'.encode()
        for scenario in ('redirect', 'bad', 'forbidden', 'malformed', 'timeout')
    ))
    redacted = result.stdout
    for secret in secrets:
        redacted = redacted.replace(secret, b'<redacted>')
    sys.stdout.buffer.write(redacted)
    if redacted != result.stdout:
        sys.exit('Secret or raw error body appeared in the playbook output')
    if server.followed_redirect:
        sys.exit('The redirected endpoint received a request')
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
