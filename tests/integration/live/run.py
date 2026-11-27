# SPDX-License-Identifier: GPL-3.0-or-later

"""Run the full integration play against a disposable Splunk Enterprise container."""

import argparse
import io
import json
import os
import re
import secrets
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

LIVE_DIR = Path(__file__).resolve().parent
COLLECTION_ROOT = LIVE_DIR.parents[2]
ASSET_DIR = '/opt/splunk-ci'
INFO_PATH = '/services/server/info?output_mode=json'
READY_TIMEOUT = 480


def prepare_keys(directory):
    extensions = directory / 'tls-extensions'
    extensions.write_text(
        'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:splunk-ci\n'
        'basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\n'
        'extendedKeyUsage=serverAuth,clientAuth\n',
    )
    commands = [
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
         '-subj', '/CN=Splunk CI CA', '-addext', 'basicConstraints=critical,CA:TRUE',
         '-keyout', 'ca.key', '-out', 'ca.pem'],
        ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', 'ssh_host_ed25519_key'],
        ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', 'ssh_client_key'],
    ]
    # The management and data-plane certificates need to share a CA.
    for name in ('server', 'server_dp'):
        commands.extend([
            ['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=splunk-ci',
             '-keyout', f'{name}.key', '-out', f'{name}.csr'],
            ['openssl', 'x509', '-req', '-days', '1', '-in', f'{name}.csr',
             '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
             '-extfile', 'tls-extensions', '-out', f'{name}.crt'],
        ])
    for command in commands:
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError(f'{command[0]} could not create test credentials: {result.stderr.strip()}')
    for name in ('server', 'server_dp'):
        with (directory / f'{name}.pem').open('wb') as bundle:
            for filename in (f'{name}.crt', f'{name}.key', 'ca.pem'):
                bundle.write((directory / filename).read_bytes())


def install_keys(container, image, directory):
    # An explicit tar stream carries the file ownership into the stopped container.
    # Docker's cp --archive would set ownership to the image's configured user.
    account = subprocess.check_output(
        ['docker', 'run', '--rm', '--entrypoint', '/bin/sh', image,
         '-c', 'id -u splunk && id -g splunk'], text=True,
    )
    splunk_uid, splunk_gid = map(int, account.split())
    assets = [
        ('server.pem', 'server.pem', splunk_uid, splunk_gid, 0o600),
        ('server_dp.pem', 'server_dp.pem', splunk_uid, splunk_gid, 0o600),
        ('ca.pem', 'ca.pem', 0, splunk_gid, 0o644),
        ('ssh_host_ed25519_key', 'ssh_host_ed25519_key', 0, 0, 0o600),
        ('ssh_client_key.pub', 'authorized_keys', 0, 0, 0o644),
    ]
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as files:
        for source, name, uid, gid, mode in assets:
            content = (directory / source).read_bytes()
            member = tarfile.TarInfo(name)
            member.uid, member.gid, member.mode, member.size = uid, gid, mode, len(content)
            files.addfile(member, io.BytesIO(content))
    subprocess.run(
        ['docker', 'cp', '-', f'{container}:{ASSET_DIR}'],
        input=archive.getvalue(), check=True,
    )


def published_port(container, port):
    mapping = subprocess.check_output(['docker', 'port', container, str(port)], text=True).strip()
    return int(mapping.removeprefix('127.0.0.1:'))


def management_request(opener, origin, basic_auth, path, fields=None):
    data = urlencode(fields).encode() if fields is not None else None
    request = Request(origin + path, data=data, headers={'Authorization': basic_auth})
    with opener.open(request, timeout=5) as response:
        return json.load(response)


def configure_token_auth(opener, origin, basic_auth, endpoint, fields):
    # The token API can still be starting after server/info is available.
    deadline = monotonic() + 120
    while True:
        try:
            return management_request(opener, origin, basic_auth, endpoint + '?output_mode=json', fields)
        except HTTPError as error:
            with error:
                if error.code != 503 or monotonic() >= deadline:
                    raise RuntimeError(f'{endpoint}: HTTP {error.code} {error.reason}') from None
        sleep(3)


def wait_for_services(container, ssh, opener, origin, basic_auth):
    deadline = monotonic() + READY_TIMEOUT
    last_status = 'Waiting for the container'
    while monotonic() < deadline:
        status, health = subprocess.check_output(
            ['docker', 'inspect', '--format', '{{.State.Status}} {{.State.Health.Status}}', container],
            text=True, timeout=10,
        ).split()
        if status != 'running' or health == 'unhealthy':
            raise RuntimeError(f'Splunk container is {status}/{health}')
        if health == 'healthy':
            try:
                management_request(opener, origin, basic_auth, INFO_PATH)
                result = subprocess.run(
                    [*ssh, 'splunk@127.0.0.1', 'id -un'],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.returncode == 0 and result.stdout.strip() == 'splunk':
                    return
                last_status = f'SSH probe: {result.stderr.strip() or result.stdout.strip()}'
            except (URLError, TimeoutError, subprocess.TimeoutExpired, ValueError) as error:
                last_status = str(error)
        else:
            last_status = f'Splunk container health: {health}'
        sleep(3)
    raise RuntimeError(f'Splunk did not become ready in {READY_TIMEOUT}s. {last_status}')


def run_playbook(directory, version, origin, port, ssh_options, password, token, redact):
    inventory = {
        'all': {
            'vars': {
                'splunk_url': origin,
                'splunk_ca_path': str(directory / 'ca.pem'),
                'splunk_username': 'admin',
                'splunk_password': password,
                'live_token': token,
                'expected_version': version,
            },
            'hosts': {
                'api_only': {
                    'ansible_connection': 'ssh',
                    'ansible_host': 'ssh-must-not-be-used.invalid',
                },
                'splunk_container': {
                    'ansible_connection': 'ssh',
                    'ansible_host': '127.0.0.1',
                    'ansible_port': port,
                    'ansible_user': 'splunk',
                    'ansible_python_interpreter': '/usr/bin/python3',
                    'ansible_ssh_common_args': shlex.join(ssh_options),
                },
            },
        },
    }
    inventory_file = directory / 'inventory.json'
    inventory_file.write_text(json.dumps(inventory))
    for mode in ([], ['--check']):
        print(f"Running Splunk {version} integration in {'check' if mode else 'normal'} mode", flush=True)
        result = subprocess.run(
            ['ansible-playbook', '-i', str(inventory_file), *mode, str(LIVE_DIR / 'test.yml')],
            env={
                **os.environ,
                'ANSIBLE_COLLECTIONS_PATH': str(COLLECTION_ROOT.parents[2]),
                'ANSIBLE_HOST_KEY_CHECKING': 'True',
                'ANSIBLE_LOCAL_TEMP': str(directory / 'ansible'),
            },
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
        )
        output = redact(result.stdout)
        print(output, end='', flush=True)
        if output != result.stdout:
            raise RuntimeError('A test credential appeared in Ansible output')
        if result.returncode:
            raise RuntimeError('The Splunk integration playbook failed')


def run_integration(version, base_image, directory):
    name = f'splunk-collection-ci-{secrets.token_hex(6)}'
    image = f'{name}:local'
    password = 'Splunk-CI9!' + secrets.token_hex(24)
    basic = b64encode(f'admin:{password}'.encode()).decode()
    credentials = [password, basic]
    container = None

    def redact(message):
        for credential in credentials:
            message = message.replace(credential, '<redacted>')
        return message

    try:
        prepare_keys(directory)
        subprocess.run(
            ['docker', 'build', '--platform', 'linux/amd64',
             '--build-arg', f'SPLUNK_IMAGE={base_image}', '--tag', image, str(LIVE_DIR)], check=True,
        )
        image_version = subprocess.check_output(
            ['docker', 'image', 'inspect', '--format', '{{ index .Config.Labels "version" }}', image],
            text=True,
        ).strip()
        # Splunk can publish a four-part product version under a three-part tag.
        if not re.fullmatch(rf'{re.escape(version)}(?:\.\d+)?', image_version):
            raise RuntimeError(f'Splunk image version {image_version!r} does not match the {version} tag')
        print(f'Testing Splunk {image_version} from the {version} image tag', flush=True)
        container = subprocess.check_output(
            ['docker', 'create', '--name', name, '--hostname', 'splunk-ci',
             '--publish', '127.0.0.1::8089', '--publish', '127.0.0.1::22',
             '--env', 'SPLUNK_PASSWORD', '--env', 'SPLUNK_START_ARGS=--accept-license',
             '--env', 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com', image],
            env={**os.environ, 'SPLUNK_PASSWORD': password}, text=True,
        ).strip()
        install_keys(container, image, directory)
        subprocess.run(['docker', 'start', container], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(
            ['docker', 'exec', '--user', 'splunk', container, 'test', '-r', f'{ASSET_DIR}/server.pem'],
            check=True,
        )
        subprocess.run(
            ['docker', 'exec', '--user', '0', container, '/usr/sbin/sshd', '-f', '/etc/ssh/sshd_config_ci'],
            check=True,
        )
        port = published_port(container, 22)
        origin = f'https://127.0.0.1:{published_port(container, 8089)}'
        known_hosts = directory / 'known_hosts'
        public_key = (directory / 'ssh_host_ed25519_key.pub').read_text()
        known_hosts.write_text(f'[127.0.0.1]:{port} {public_key}')
        ssh_options = [
            '-F', '/dev/null', '-i', str(directory / 'ssh_client_key'),
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known_hosts}',
        ]
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(
            cafile=directory / 'ca.pem',
        )))
        auth = f'Basic {basic}'
        print(f'Waiting for Splunk {version} HTTPS and SSH readiness', flush=True)
        wait_for_services(container, ['ssh', *ssh_options, '-p', str(port)], opener, origin, auth)
        configure_token_auth(opener, origin, auth, '/services/admin/token-auth/tokens_auth',
                             {'disabled': 'false'})
        document = configure_token_auth(opener, origin, auth, '/services/authorization/tokens',
                                        {'name': 'admin', 'audience': 'collection-ci', 'expires_on': '+1h'})
        token = document['entry'][0]['content']['token']
        if not isinstance(token, str) or not token:
            raise RuntimeError('Splunk did not return a bearer token')
        credentials.append(token)
        run_playbook(directory, image_version, origin, port, ssh_options, password, token, redact)
    except (OSError, RuntimeError, ValueError, LookupError, subprocess.SubprocessError) as error:
        print(redact(str(error)), file=sys.stderr)
        if container:
            logs = subprocess.run(['docker', 'logs', '--tail', '100', container],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
            print(redact(logs.stdout), file=sys.stderr, end='')
        return 1
    finally:
        if container:
            subprocess.run(['docker', 'rm', '--force', '--volumes', container], check=False,
                           stdout=subprocess.DEVNULL)
        subprocess.run(['docker', 'image', 'rm', image], check=False, capture_output=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', help='exact Splunk patch version to assert')
    parser.add_argument('image', help='digest-pinned official Splunk RHEL 9 image')
    args = parser.parse_args()
    expected_image = rf'splunk/splunk:{re.escape(args.version)}-rhel9@sha256:[0-9a-f]{{64}}'
    if not re.fullmatch(r'10\.\d+\.\d+', args.version) or not re.fullmatch(expected_image, args.image):
        parser.error('specify a 10.x patch version and its digest-pinned splunk/splunk RHEL 9 image')
    if Path.cwd() != COLLECTION_ROOT or COLLECTION_ROOT.parts[-3:] != ('ansible_collections', 'pyrodie18', 'splunk'):
        parser.error('run from the ansible_collections/pyrodie18/splunk collection root')
    if os.environ.get('SPLUNK_CI_ACCEPT_TERMS') != 'true':
        parser.error('after accepting the Splunk terms, set SPLUNK_CI_ACCEPT_TERMS=true')
    for tool in ('docker', 'openssl', 'ssh', 'ssh-keygen', 'ansible-playbook'):
        if not shutil.which(tool):
            parser.error(f'{tool} is required for the live integration suite')
    with TemporaryDirectory(prefix='splunk-collection-ci-') as path:
        return run_integration(args.version, args.image, Path(path))


if __name__ == '__main__':
    sys.exit(main())
