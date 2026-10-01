#!/usr/bin/env python3
"""Guarded unattended WAAP lifecycle. No local test establishes protection efficacy.

State, plans, outputs and receipts live outside the checkout. SSH uses dedicated
accept-new known_hosts (TOFU); subsequent host-key changes fail closed. Commands
are argv-only, have deadlines, and never expose Terraform output in diagnostics.
"""
import argparse
import fcntl
import fnmatch
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

FIXED = {
    'xc_url': 'https://f5-sales-demo.console.ves.volterra.io',
    'namespace': 'webapp-api-protection',
    'domains': ['www.f5-sales-demo.com', 'api.f5-sales-demo.com'],
}

AZURE_TYPES = {'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet',
               'azurerm_public_ip', 'azurerm_network_security_group',
               'azurerm_network_interface', 'azurerm_network_interface_security_group_association',
               'azurerm_linux_virtual_machine'}
XC_TYPES = {'xcsh_healthcheck', 'xcsh_origin_pool', 'xcsh_app_firewall',
            'xcsh_malicious_user_mitigation', 'xcsh_user_identification',
            'xcsh_api_discovery', 'xcsh_http_loadbalancer', 'xcsh_api_definition',
            'xcsh_service_policy', 'xcsh_rate_limiter', 'xcsh_rate_limiter_policy',
            'xcsh_app_api_group', 'xcsh_data_type', 'xcsh_route',
            'xcsh_sensitive_data_policy', 'xcsh_waf_exclusion_policy',
            'xcsh_bgp_asn_set', 'xcsh_ip_prefix_set', 'xcsh_api_testing'}
# Exact collection names verified against the embedded API catalog.
XC_COLLECTIONS = {
    'xcsh_healthcheck': 'healthchecks', 'xcsh_origin_pool': 'origin_pools',
    'xcsh_app_firewall': 'app_firewalls', 'xcsh_http_loadbalancer': 'http_loadbalancers',
    'xcsh_malicious_user_mitigation': 'malicious_user_mitigations',
    'xcsh_user_identification': 'user_identifications', 'xcsh_api_discovery': 'api_discoverys',
    'xcsh_api_definition': 'api_definitions', 'xcsh_service_policy': 'service_policys',
    'xcsh_rate_limiter': 'rate_limiters', 'xcsh_rate_limiter_policy': 'rate_limiter_policys',
}


class Blocked(RuntimeError):
    """A required gate has not passed; retain partial provisioning."""


def quota_count(value):
    """Normalize exact JSON counts without accepting ambiguous or unsafe numbers."""
    maximum = 2 ** 53 - 1
    if isinstance(value, str):
        if not re.fullmatch(r'[0-9]{1,16}', value):
            raise Blocked('malformed eastus2 VM quota count')
        value = int(value)
    if (type(value) not in (int, float) or not 0 <= value <= maximum or
            int(value) != value):
        raise Blocked('malformed eastus2 VM quota count')
    return int(value)


def config_values(value):
    if isinstance(value, dict) and 'backend' in value:
        raise Blocked('backend config is no longer accepted; select local state using --state-dir; explicit migration required for initialized remote state')
    if not isinstance(value, dict) or set(value) - set(FIXED) - {'subscription_id', 'tenant_id', 'ssh_key', 'expected_azure_user'}:
        raise Blocked('unknown config fields; only fixed scope, approved Azure IDs, SSH key and authorized Azure user accepted')
    for key, expected in FIXED.items():
        if key in value and value[key] != expected:
            raise Blocked('fixed identity/scope override rejected: ' + key)
    result = dict(FIXED)
    result.update(value)
    if 'expected_azure_user' not in result and 'DEMO_AZURE_USER' in os.environ:
        result['expected_azure_user'] = os.environ['DEMO_AZURE_USER']
    if 'expected_azure_user' in result:
        user = result['expected_azure_user']
        if (not isinstance(user, str) or not 1 <= len(user) <= 320
                or not re.fullmatch(r'[!-?A-~]+@[!-?A-~]+', user)):
            raise Blocked('authorized Azure user must be a bounded printable UPN without whitespace')
    for key, environment in (('subscription_id', 'DEMO_AZURE_SUBSCRIPTION_ID'),
                             ('tenant_id', 'DEMO_AZURE_TENANT_ID')):
        approved = result.get(key, os.environ.get(environment))
        if key not in result and environment not in os.environ:
            raise Blocked('approved Azure ' + key + ' missing; supply private operator config or ' + environment)
        if not isinstance(approved, str) or not re.fullmatch(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', approved):
            raise Blocked('approved Azure ' + key + ' must be a canonical UUID')
        result[key] = approved.lower()
    return result


def secure_directory(path, checkout):
    path = path.expanduser().absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise Blocked('state directory must not traverse symlinks')
    path = path.resolve()
    if path == checkout or checkout in path.parents:
        raise Blocked('state directory must be outside the checkout')
    if path.exists() and (path.is_symlink() or path.stat().st_uid != os.getuid()):
        raise Blocked('state directory ownership is unsafe')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def secure_artifact(path, private=True):
    """Reject foreign/symlink artifacts before reading or changing their permissions."""
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise Blocked('persistent artifact must not traverse symlinks')
    if path.exists():
        if path.stat().st_uid != os.getuid() or not (path.is_file() or path.is_dir()):
            raise Blocked('persistent artifact ownership/type is unsafe')
        executable = path.is_file() and os.access(path, os.X_OK) and not path.name.endswith(('.tfstate', '.backup', '.json'))
        if private:
            path.chmod(0o700 if path.is_dir() or executable else 0o600)


def private_json(path):
    secure_artifact(path)
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        raise Blocked('persistent JSON artifact unreadable; explicit migration required') from None


def operator_config(path, checkout):
    """Read only caller-owned, private operator input outside the public checkout."""
    path = path.expanduser().absolute()
    secure_artifact(path, private=False)
    if path.resolve() == checkout.resolve() or checkout.resolve() in path.resolve().parents:
        raise Blocked('operator config must be outside the checkout')
    if not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise Blocked('operator config must be an existing private mode 0600 file')
    return private_json(path)


def save_json(path, value):
    secure_artifact(path)
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def guard_plan(plan, mode, owned=None, persistent=()):
    """Reject protected ownership, replacement and unowned deletion."""
    for item in plan.get('resource_changes', []):
        if item.get('mode') == 'data':
            continue
        actions = item['change']['actions']
        kind = item.get('type', '')
        if kind == 'xcsh_namespace':
            raise Blocked('namespace owned by application plan; explicit external migration required')
        if kind not in AZURE_TYPES | XC_TYPES and actions != ['no-op']:
            raise Blocked('protected/unknown application resource type: ' + kind)
        before = item['change'].get('before') or {}
        if before.get('id') in persistent and actions != ['no-op']:
            raise Blocked('persistent resource in application plan')
        if mode == 'noop' and actions != ['no-op']:
            raise Blocked('nonzero drift; verify never repairs infrastructure')
        if mode == 'destroy':
            if actions not in (['delete'], ['no-op']):
                raise Blocked('destroy plan includes non-delete change')
            if owned is not None and actions == ['delete'] and owned.get(item['address']) != before.get('id'):
                raise Blocked('destroy plan includes resource not in captured state')
    if mode == 'noop' and any(v.get('actions') != ['no-op'] for v in plan.get('output_changes', {}).values()):
        raise Blocked('nonzero output drift')


def managed_resources(module):
    yield from (r for r in module.get('resources', []) if r.get('mode') == 'managed')
    for child in module.get('child_modules', []):
        yield from managed_resources(child)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Blocked('XC redirect refused to protect tenant credentials')


class Lifecycle:
    def __init__(self, args, root=None):
        os.umask(0o077)
        self.root = root or Path(__file__).resolve().parents[1]
        base = Path.home() / '.local/state/waap-showcase'
        operator = args.config or base / 'operator.json'
        supplied = operator_config(operator, self.root) if args.config or operator.exists() or operator.is_symlink() else {}
        self.config = config_values(supplied)
        self.scope = {key: self.config[key] for key in (*FIXED, 'subscription_id', 'tenant_id')}
        self.state = secure_directory(args.state_dir or base / self.scope['subscription_id'], self.root)
        for name in ('operation-receipt.json', 'run-manifest.json'):
            previous = self.state / name
            if previous.exists():
                saved = private_json(previous)
                old_scope = saved.get('scope', saved)
                if any(key in old_scope and old_scope[key] != self.scope[key]
                       for key in ('subscription_id', 'tenant_id')):
                    raise Blocked('existing state approval scope mismatch; explicit external migration required')
        for path in self.state.rglob('*'):
            secure_artifact(path, private=False)
        self.deadline = time.monotonic() + args.timeout_seconds
        self.operation = args.operation
        self.receipt = {'schema_version': 1, 'operation': self.operation, 'scope': self.scope, 'phases': [], 'status': 'running'}
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('TF_', 'ARM_'))}
        self.env.update(TF_IN_AUTOMATION='1', TF_INPUT='0', TF_CLI_CONFIG_FILE='/dev/null',
                        ARM_USE_CLI='true', ARM_USE_AZUREAD='true',
                        ARM_SUBSCRIPTION_ID=self.scope['subscription_id'], ARM_TENANT_ID=self.scope['tenant_id'])
        self.key = Path(self.config.get('ssh_key', '~/.ssh/id_ed25519')).expanduser().resolve()
        self.outputs = None
        self.backend = {'path': str(self.state / 'application.tfstate')}
        self.persistent = {}
        self.namespace_uid = None
        self.app = self.root / 'terraform'
        self.namespace_root = self.app / 'namespace'
        self.namespace_backend = {'path': str(self.state / 'namespace.tfstate')}
        self.vars = self.state / 'application.tfvars.json'
        self.known_hosts = self.state / 'known_hosts'
        self.app_ready = False
        self.opener = urllib.request.build_opener(NoRedirect())

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise Blocked('operation deadline exceeded')
        return value

    def phase(self, name, status='passed'):
        self.receipt['phases'].append({'name': name, 'status': status, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
        save_json(self.state / 'operation-receipt.json', self.receipt)

    def run(self, argv, cwd=None, allowed=(0,), env=None):
        """No shell; kill the complete process group on timeout/interruption."""
        began = time.monotonic()
        budget = self.remaining()
        proc = subprocess.Popen([str(a) for a in argv], cwd=cwd or self.root,
                                env=env or self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=budget)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.stdout.close()
                proc.stderr.close()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            self.record_command(argv, proc.returncode, began, 'interrupted-or-deadline')
            raise
        category = 'none'
        if proc.returncode not in allowed:
            category = 'upstream-output-withheld'
            lower = stderr.lower()
            for pattern, label in [(r'(?:^|\s)(?:http[ -])?403(?=\s|$|[,;:)])', 'HTTP-403-permission'),
                                   (r'\bauthorizationpermissionmismatch\b', 'blob-data-permission'),
                                   (r'\bauthorizationfailed\b', 'permission'),
                                   (r'\balready exists\b', 'resource-conflict'),
                                   (r'(?:^|\s)(?:http[ -])?401(?=\s|$|[,;:)])', 'authentication'),
                                   (r'(?:^|\s)(?:http[ -])?400(?=\s|$|[,;:)])', 'HTTP-400-configuration'),
                                   (r'\binvalidapiversionparameter\b', 'arm-api-version-unsupported'),
                                   (r'\bunsupportedapiversion\b', 'arm-api-version-unsupported'),
                                   (r'(?:^|\s)quota(?=\s|$|[:;,])', 'quota'),
                                   (r'(?:^|\s)timeout(?=\s|$|[:;,])', 'timeout')]:
                if re.search(pattern, lower):
                    category = label
                    break
            # Terraform's state-lock diagnostic is not any occurrence of "lock"
            # (provider payloads routinely include fields such as blocking_page).
            if category == 'upstream-output-withheld' and Path(str(argv[0])).name == 'terraform':
                if re.search(r'\bstate lock\b', lower):
                    category = 'state-lock'
        self.record_command(argv, proc.returncode, began, category)
        if proc.returncode not in allowed:
            raise Blocked('required subprocess failed: ' + Path(str(argv[0])).name + ' exit ' + str(proc.returncode) + ' (' + category + ')')
        return stdout, proc.returncode

    def record_command(self, argv, code, began, category):
        # Whitelisted summaries only: no argv, environment, stdout or state data.
        program = Path(str(argv[0])).name
        verb = str(argv[2]) if program == 'terraform' and len(argv) > 2 else 'invocation'
        if verb not in ('init', 'fmt', 'validate', 'plan', 'apply', 'output', 'state', 'show', 'import'):
            verb = 'invocation'
        self.receipt.setdefault('commands', []).append({'program': program, 'verb': verb, 'exit_code': code,
                                                       'seconds': round(time.monotonic() - began, 3), 'diagnostic': category})
        save_json(self.state / 'operation-receipt.json', self.receipt)

    def az(self, *argv):
        return json.loads(self.run(['az', *argv, '--subscription', self.scope['subscription_id'], '-o', 'json'])[0])

    def tf(self, directory, *argv, allowed=(0,)):
        os.umask(0o077)
        self.local_backend_check()
        if any(str(a).startswith(('-lock=false', '-state=', '-state-out=', '-backup=', '-reconfigure', '-migrate-state', '-force-copy', '-backend=false')) for a in argv):
            raise Blocked('Terraform state/locking override prohibited')
        roots = {self.app: 'application-data', self.namespace_root: 'namespace-data'}
        if directory not in roots:
            raise Blocked('unknown Terraform root; refusing state selection')
        if directory == self.namespace_root and ('destroy' in argv or any(str(a).startswith('-destroy') for a in argv)):
            raise Blocked('namespace Terraform destroy prohibited; application state only')
        data = self.state / roots[directory]
        if argv and argv[0] in ('apply', 'plan', 'output', 'state', 'show', 'import') and not (data / 'terraform.tfstate').exists():
            raise Blocked('local backend not initialized; refusing default checkout state')
        env = dict(self.env, TF_DATA_DIR=str(data), TF_WORKSPACE='default')
        try:
            return self.run(['terraform', '-chdir=' + str(directory), *argv], allowed=allowed, env=env)
        finally:
            for path in self.state.rglob('*'):
                secure_artifact(path, private=False)
            label = roots[directory].removesuffix('-data')
            for path in (data, data / 'terraform.tfstate', self.state / (label + '.tfstate'),
                         self.state / (label + '.tfstate.backup')):
                secure_artifact(path)

    def xc(self, path, allow_absent=False):
        request = urllib.request.Request(self.scope['xc_url'] + path, headers={'Authorization': 'APIToken ' + self.env['XCSH_API_TOKEN']})
        try:
            with self.opener.open(request, timeout=min(30, self.remaining())) as response:
                chunks, size = [], 0
                while response.fp is not None:
                    response.fp.raw._sock.settimeout(self.remaining())
                    chunk = response.read1(65536)
                    self.remaining()
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 8 * 1024 * 1024:
                        raise Blocked('XC response exceeded bounded evidence size')
                    chunks.append(chunk)
                if getattr(response, 'length', None) not in (None, 0):
                    raise Blocked('truncated XC response')
                return json.loads(b''.join(chunks))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_absent:
                return None
            raise Blocked('XC authentication/permission check failed: HTTP ' + str(exc.code)) from None
        except (urllib.error.URLError, TimeoutError):
            raise Blocked('XC connectivity check failed') from None

    def preflight(self, deploying):
        for tool in ('terraform', 'az', 'ssh', 'ssh-keygen', 'curl', 'bash', 'python3', 'dig'):
            if not shutil.which(tool):
                raise Blocked('missing prerequisite: ' + tool)
        for path in (self.root / 'scripts/demo-verify.sh', self.root / 'scripts/swagger-upload.sh', self.app / 'showcase.tfvars.json', self.app / 'fixtures/showcase-openapi.json'):
            if not path.is_file():
                raise Blocked('missing required artifact: ' + str(path.relative_to(self.root)))
        self.local_backend_check()
        if self.env.get('XCSH_API_URL', '').rstrip('/') != self.scope['xc_url'] or not self.env.get('XCSH_API_TOKEN'):
            raise Blocked('XC URL/token environment missing or wrong tenant')
        if not self.key.is_file() or self.key.stat().st_mode & 0o077:
            raise Blocked('SSH private key missing or unsafe permissions')
        public = self.key.with_name(self.key.name + '.pub')
        derived = self.run(['ssh-keygen', '-y', '-P', '', '-f', self.key])[0].strip().split()[:2]
        if not public.is_file() or public.read_text().split()[:2] != derived:
            raise Blocked('SSH public/private key mismatch')
        expected_user = self.config.get('expected_azure_user')
        if expected_user is None:
            raise Blocked('authorized Azure user missing; supply private operator config or DEMO_AZURE_USER')
        account = self.az('account', 'show')
        if account.get('id') != self.scope['subscription_id'] or account.get('tenantId') != self.scope['tenant_id'] or account.get('state') != 'Enabled':
            raise Blocked('Azure authenticated identity/tenant/subscription mismatch')
        if account.get('user', {}).get('type') != 'user':
            raise Blocked('requires existing Azure CLI user authentication; no login automation')
        actual_user = account.get('user', {}).get('name')
        if not isinstance(actual_user, str) or actual_user.casefold() != expected_user.casefold():
            raise Blocked('Azure authenticated human identity mismatch')
        self.namespace_prepare()
        addon = self.xc('/api/web/namespaces/system/addon_services/f5xc-waap-standard/activation-status')
        state = addon.get('state')
        if state != 'AS_SUBSCRIBED':
            raise Blocked('WAAP entitlement is not AS_SUBSCRIBED')
        # Check the shared parent zone before creation, not LB-managed host A records.
        # Readiness verifies both concrete domain endpoints after Terraform creates them.
        soa = self.run(['dig', '+time=2', '+tries=1', '+short', 'SOA', 'f5-sales-demo.com'])[0].strip().split()
        if len(soa) != 7 or not all(value.isdigit() for value in soa[2:]):
            raise Blocked('shared public DNS zone SOA unavailable')
        if deploying:
            self.capacity_permissions()
        # Ignore user CLI configuration, caches and development overrides.
        self.env['TF_CLI_CONFIG_FILE'] = '/dev/null'
        if not self.known_hosts.exists():
            self.known_hosts.touch(mode=0o600)
        if self.known_hosts.is_symlink():
            raise Blocked('unsafe known_hosts symlink')
        self.known_hosts.chmod(0o600)
        self.phase('authenticated-scope-prerequisites-entitlement-dns')

    def capacity_permissions(self):
        subscription = '/subscriptions/' + self.scope['subscription_id']
        permissions = self.az('rest', '--method', 'get', '--url', 'https://management.azure.com' + subscription + '/providers/Microsoft.Authorization/permissions?api-version=2022-04-01').get('value', [])
        required = ['Microsoft.Resources/subscriptions/resourceGroups/write', 'Microsoft.Compute/virtualMachines/write',
                    'Microsoft.Network/virtualNetworks/write', 'Microsoft.Network/publicIPAddresses/write']
        for action in required:
            if not any(any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in p.get('actions', [])) and
                       not any(fnmatch.fnmatchcase(action.lower(), a.lower()) for a in p.get('notActions', [])) for p in permissions):
                raise Blocked('Azure effective permissions missing required write: ' + action)
        released = {'cores': 0, 'standarddsv3family': 0, 'standardfsv2family': 0}
        if self.operation == 'rebuild':
            # Prove the complete foundation and exact application ownership BEFORE deletion.
            self.namespace_prepare()
            self.app_init()
            if not self.vars.is_file():
                raise Blocked('missing secure deployed variable receipt')
            self.inventory()
            self.verify_fixture()
            seen = set()
            for resource in self.resources:
                if resource['type'] != 'azurerm_linux_virtual_machine':
                    continue
                values = resource['values']
                rid = values['id']
                if rid.lower() in seen:
                    raise Blocked('duplicate owned VM allocation')
                seen.add(rid.lower())
                vm = self.az('vm', 'show', '--ids', rid, '--show-details')
                size = vm.get('hardwareProfile', {}).get('vmSize')
                family = {'Standard_D16s_v3': 'standarddsv3family',
                          'Standard_F16s_v2': 'standardfsv2family'}.get(size)
                if vm.get('id', '').lower() != rid.lower() or vm.get('location', '').lower() != 'eastus2' or not family or size != values.get('size'):
                    raise Blocked('owned VM allocation identity/SKU mismatch')
                power = vm.get('powerState')
                if power in ('VM running', 'VM stopped'):
                    released['cores'] += 16
                    released[family] += 16
                elif power != 'VM deallocated':
                    raise Blocked('owned VM allocation state unavailable')
        usage = self.az('vm', 'list-usage', '--location', 'eastus2')
        if not isinstance(usage, list):
            raise Blocked('unavailable eastus2 VM quota response')
        for name, needed in [('cores', 32), ('standarddsv3family', 16), ('standardfsv2family', 16)]:
            entries = [u for u in usage if isinstance(u, dict) and
                       isinstance(u.get('name'), dict) and
                       str(u['name'].get('value', '')).lower() == name]
            if len(entries) != 1 or entries[0].get('unit') != 'Count':
                raise Blocked('unavailable/unknown-unit eastus2 VM quota: ' + name)
            entry = entries[0]
            current = quota_count(entry.get('currentValue'))
            limit = quota_count(entry.get('limit'))
            if released[name] > current or limit - current + released[name] < needed:
                raise Blocked('insufficient/unavailable eastus2 VM quota: ' + name)
        skus = self.az('vm', 'list-skus', '--location', 'eastus2', '--resource-type', 'virtualMachines', '--all')
        for name in ('Standard_D16s_v3', 'Standard_F16s_v2'):
            matches = [s for s in skus if s.get('name') == name]
            if len(matches) != 1 or any(r.get('type') == 'Location' for r in matches[0].get('restrictions', [])):
                raise Blocked('subscription-aware eastus2 SKU unavailable: ' + name)
        # A repair rebuild authorizes deletion by ownership and capacity, not app health.
        # Fresh deployment still must pass readiness before starting traffic.
        self.phase('azure-permissions-quota-skus')

    def namespace_prepare(self):
        """Read live identity and persist evidence; never mutate Terraform or the tenant."""
        self.local_backend_check()
        persistent = {'namespace': 'system/' + self.scope['namespace']}
        saved = self.state / 'persistent.json'
        if saved.exists() and private_json(saved) != persistent:
            raise Blocked('existing foundation receipt incompatible; explicit external migration required')
        manifest = self.state / 'run-manifest.json'
        if manifest.exists():
            previous = private_json(manifest)
            if previous.get('persistent_resource_ids') != persistent or previous.get('azure_preserved') != []:
                raise Blocked('existing run foundation incompatible; explicit external migration required')
        namespace = self.xc('/api/web/namespaces/' + self.scope['namespace'], allow_absent=True)
        uid = (namespace or {}).get('system_metadata', {}).get('uid')
        if not uid or (namespace or {}).get('metadata', {}).get('name') != self.scope['namespace']:
            raise Blocked('externally managed namespace missing or identity unavailable')
        namespace_receipt = self.state / 'namespace-receipt.json'
        if ((self.state / 'namespace.tfstate').exists() and not namespace_receipt.exists()
                and not manifest.exists() and not self.namespace_uid):
            raise Blocked('managed namespace UID evidence missing; adoption refused')
        identity = {'path': '/api/web/namespaces/' + self.scope['namespace'], 'uid': uid}
        if namespace_receipt.exists() and private_json(namespace_receipt) != identity:
            raise Blocked('persistent namespace UID changed; explicit external migration required')
        old_uid = self.namespace_uid
        if manifest.exists():
            preserved = private_json(manifest).get('xc_preserved', [])
            expected = [identity]
            if preserved != expected:
                raise Blocked('persistent namespace identity changed; explicit external migration required')
        if old_uid and old_uid != uid:
            raise Blocked('persistent namespace UID changed')
        self.namespace_uid = uid
        self.persistent = persistent
        save_json(saved, persistent)
        save_json(namespace_receipt, identity)
        self.phase('namespace-identity-preserved')

    def namespace_state_identity(self):
        value = json.loads(self.tf(self.namespace_root, 'show', '-json')[0])
        resources = list(managed_resources(value.get('values', {}).get('root_module', {})))
        if (len(resources) != 1 or resources[0].get('address') != 'xcsh_namespace.this'
                or resources[0].get('type') != 'xcsh_namespace'
                or resources[0].get('values', {}).get('name') != self.scope['namespace']
                or resources[0].get('values', {}).get('id') != self.scope['namespace']):
            raise Blocked('namespace Terraform state identity mismatch; adoption refused')

    def namespace_tf_prepare(self, create=False):
        """Import only the observed namespace, never create/replace/delete it."""
        if create and self.operation not in ('deploy', 'rebuild'):
            raise Blocked('namespace import/apply permitted only during deployment')
        state = self.state / 'namespace.tfstate'
        exists = state.exists()
        if not exists and not create:
            raise Blocked('namespace Terraform state missing; deploy must import foundation first')
        if not self.namespace_uid and not (self.state / 'namespace-receipt.json').is_file():
            raise Blocked('namespace UID evidence missing; preflight must confirm identity before import')
        self.namespace_prepare()
        backend = self.state / 'namespace-backend.json'
        save_json(backend, self.namespace_backend)
        self.tf(self.namespace_root, 'init', '-input=false', '-backend-config=' + str(backend))
        self.tf(self.namespace_root, 'validate')
        if not exists:
            # Re-read against the UID receipt immediately before the local-state import.
            self.namespace_prepare()
            # Namespace is tenant-scoped: provider 12.0.2 imports the bare name,
            # not the logical system/name receipt used to identify preservation.
            self.tf(self.namespace_root, 'import', '-input=false', 'xcsh_namespace.this', self.scope['namespace'])
        self.namespace_state_identity()
        plan = self.state / 'namespace.plan'
        secure_artifact(plan)
        _, code = self.tf(self.namespace_root, 'plan', '-input=false', '-detailed-exitcode',
                          '-out=' + str(plan), allowed=(0, 2))
        secure_artifact(plan)
        value = json.loads(self.tf(self.namespace_root, 'show', '-json', str(plan))[0])
        changes = value.get('resource_changes', [])
        if (len(changes) != 1 or changes[0].get('mode', 'managed') != 'managed'
                or changes[0].get('address') != 'xcsh_namespace.this'
                or changes[0].get('type') != 'xcsh_namespace'
                or changes[0].get('change', {}).get('actions') != ['no-op']
                or changes[0].get('change', {}).get('importing') or value.get('deferred_changes')):
            raise Blocked('namespace plan must preserve the sole namespace; mutation refused')
        change = changes[0]['change']
        for key in ('before', 'after'):
            identity = change.get(key) or {}
            if identity.get('name') != self.scope['namespace'] or identity.get('id') != self.scope['namespace']:
                raise Blocked('namespace plan identity mismatch')
        if change.get('after_unknown') and any(change['after_unknown'].get(k) for k in ('name', 'id')):
            raise Blocked('namespace plan identity unknown')
        for name, output in value.get('output_changes', {}).items():
            if (name not in ('namespace_name', 'namespace_id') or output.get('after_unknown')
                    or output.get('after') != self.scope['namespace']):
                raise Blocked('namespace plan output identity mismatch')
        if not create and code != 0:
            raise Blocked('namespace preservation plan is not zero-change')
        if create:
            self.namespace_prepare()
            self.tf(self.namespace_root, 'apply', '-input=false', str(plan))
            self.namespace_state_identity()
        self.namespace_prepare()
        self.phase('namespace-terraform-preserved')

    def local_backend_check(self):
        """Never silently adopt checkout, remote, alternate-path or unknown state."""
        for path in self.state.rglob('*'):
            secure_artifact(path, private=False)
        roots = ((self.app, 'application', self.backend),
                 (self.namespace_root, 'namespace', self.namespace_backend))
        permitted_state = set()
        for directory, label, backend in roots:
            for path in (directory / 'terraform.tfstate', directory / 'terraform.tfstate.backup',
                         directory / '.terraform/terraform.tfstate', directory / 'terraform.tfstate.d'):
                if path.exists() or path.is_symlink():
                    raise Blocked('checkout has ' + label + ' state/backend metadata; explicit migration required')
            data = self.state / (label + '-data')
            secure_artifact(data)
            metadata = data / 'terraform.tfstate'
            paths = (self.state / (label + '.tfstate'), self.state / (label + '.tfstate.backup'))
            permitted_state.update((metadata, *paths))
            if metadata.exists():
                stored = private_json(metadata)
                cached = stored.get('backend', {}) if isinstance(stored, dict) else {}
                config = cached.get('config', {}) if isinstance(cached, dict) else None
                if not isinstance(config, dict):
                    raise Blocked('unknown backend metadata requires explicit migration')
                if (cached.get('type') != 'local' or config.get('path') != backend['path']
                        or config.get('workspace_dir') not in (None, '')
                        or config.get('backup') not in (None, '')):
                    raise Blocked('initialized remote/different backend requires explicit migration')
            for path in paths:
                if path.exists():
                    stored = private_json(path)
                    if not isinstance(stored, dict) or not isinstance(stored.get('version'), int) or not isinstance(stored.get('resources'), list):
                        raise Blocked('unknown ' + label + ' state requires explicit migration')
                    if label == 'namespace' and (len(stored['resources']) > 1 or any(
                            not isinstance(r, dict) or r.get('mode') != 'managed' or r.get('type') != 'xcsh_namespace'
                            or r.get('name') != 'this' or r.get('module') or len(r.get('instances', [])) != 1
                            or r['instances'][0].get('attributes', {}).get('name') != self.scope['namespace']
                            or r['instances'][0].get('attributes', {}).get('id') != self.scope['namespace']
                            for r in stored['resources'])):
                        raise Blocked('unknown namespace state identity requires explicit migration')
            environment = data / 'environment'
            if environment.exists() and environment.read_text().strip() not in ('', 'default'):
                raise Blocked('nondefault Terraform workspace requires explicit migration')
            generated = self.state / ('backend.json' if label == 'application' else 'namespace-backend.json')
            if generated.exists() and private_json(generated) != backend:
                if metadata.exists() or any(self.state.rglob('*.tfstate')) or any(self.state.rglob('*.tfstate.backup')):
                    raise Blocked('existing backend config with state requires explicit migration')
        for path in self.state.rglob('*'):
            if path.name.endswith(('.tfstate', '.tfstate.backup')) and path not in permitted_state:
                raise Blocked('unexpected persistent state/backend metadata requires explicit migration')
        if (self.state / 'terraform.tfstate.d').exists():
            raise Blocked('alternate workspace state requires explicit migration')
        return self.state / 'backend.json'

    def app_init(self):
        backend = self.local_backend_check()
        save_json(backend, self.backend)
        # No reconfigure/migrate-state/force-copy: preserve state and native file locking.
        self.tf(self.app, 'init', '-input=false', '-backend-config=' + str(backend))
        # Runtime source only: fixtures and test HCL have their own authoring gates.
        for directory in (self.app, *sorted((self.app / 'modules').glob('*'))):
            files = sorted(directory.glob('*.tf'))
            if files:
                self.tf(self.app, 'fmt', '-check', *files)
        self.tf(self.app, 'validate')
        self.app_ready = True
        self.phase('application-secure-local-backend')

    def guard_conflicts(self, plan):
        # Azure resource-group PUT can silently adopt existing groups: stop first.
        for item in plan.get('resource_changes', []):
            if item.get('mode') == 'data' or 'create' not in item['change']['actions']:
                continue
            after = item['change'].get('after') or {}
            if item['type'] == 'azurerm_resource_group':
                name = after.get('name')
                if not name or self.az('group', 'exists', '--name', name):
                    raise Blocked('out-of-state Azure resource-group conflict or unknown name')
            if item['type'] in XC_TYPES:
                collection = XC_COLLECTIONS.get(item['type'])
                name, namespace = after.get('name'), after.get('namespace')
                if not collection or namespace != self.scope['namespace'] or not re.fullmatch(r'[a-z][a-z0-9-]*[a-z0-9]', name or ''):
                    raise Blocked('unknown XC creation identity; conflict check refused')
                if self.xc('/api/config/namespaces/' + namespace + '/' + collection + '/' + name, allow_absent=True) is not None:
                    raise Blocked('out-of-state XC resource conflict; adoption refused')

    def guard_group_children(self, resources):
        ids = {r['values']['id'].split('|')[0].lower() for r in resources if r['type'] in AZURE_TYPES}
        # OS disks are VM-owned implicit resources rather than separate TF addresses.
        for item in resources:
            if item['type'] == 'azurerm_linux_virtual_machine':
                vm = self.az('vm', 'show', '--ids', item['values']['id'])
                disk = vm.get('storageProfile', {}).get('osDisk', {}).get('managedDisk', {}).get('id')
                if not disk:
                    raise Blocked('owned VM OS-disk identity unavailable')
                ids.add(disk.lower())
        for item in resources:
            if item['type'] == 'azurerm_resource_group':
                children = self.az('resource', 'list', '--resource-group', item['values']['name'])
                if any(c['id'].lower() not in ids for c in children):
                    raise Blocked('resource group contains unowned children; refusing group destruction')


    def plan(self, name, mode='deploy', owned=None):
        path = self.state / (name + '.plan')
        secure_artifact(path)
        argv = ['plan', '-input=false', '-detailed-exitcode', '-var-file=' + str(self.vars), '-out=' + str(path)]
        if mode == 'destroy':
            argv.append('-destroy')
        _, code = self.tf(self.app, *argv, allowed=(0, 2))
        secure_artifact(path)
        parsed = json.loads(self.tf(self.app, 'show', '-json', str(path))[0])
        guard_plan(parsed, mode, owned, self.persistent.values())
        if mode == 'deploy':
            self.guard_conflicts(parsed)
        if mode == 'noop' and code != 0:
            raise Blocked('nonzero detailed-exitcode drift')
        self.phase(name + '-guarded-plan')
        return path

    def get_outputs(self):
        outputs = json.loads(self.tf(self.app, 'output', '-json')[0])
        if 'showcase' not in outputs:
            raise Blocked('missing showcase outputs; state lost or incomplete')
        self.outputs = outputs['showcase']['value']
        if self.outputs.get('namespace') != self.scope['namespace'] or sorted(self.outputs.get('domains', [])) != sorted(self.scope['domains']):
            raise Blocked('outputs scope mismatch')
        save_json(self.state / 'outputs.json', outputs)

    def owned_guest(self, resources, role, candidate=None):
        """Join the exact module VM/NIC/PIP state to Azure before any SSH."""
        if self.config['subscription_id'] != self.scope['subscription_id'] or self.config['namespace'] != self.scope['namespace']:
            raise Blocked('owned SSH configuration scope mismatch')
        module = {'origin': 'origin_server', 'generator': 'traffic_generator'}[role]
        prefix = 'module.' + module + '.'
        records = {}
        for kind in ('linux_virtual_machine', 'network_interface', 'public_ip'):
            address = prefix + 'azurerm_' + kind + '.main'
            matches = [r for r in resources if r.get('address') == address
                       and r.get('type') == 'azurerm_' + kind]
            if len(matches) != 1:
                raise Blocked('owned ' + role + ' ' + kind + ' unavailable')
            records[kind] = matches[0]['values']
        vm, nic, pip = (records[k] for k in ('linux_virtual_machine', 'network_interface', 'public_ip'))
        scope = '/subscriptions/' + self.scope['subscription_id'] + '/resourceGroups/'
        kinds = {'linux_virtual_machine': 'Microsoft.Compute/virtualMachines',
                 'network_interface': 'Microsoft.Network/networkInterfaces',
                 'public_ip': 'Microsoft.Network/publicIPAddresses'}
        for kind, values in records.items():
            if not re.fullmatch(re.escape(scope) + r'[^/]+/providers/' + re.escape(kinds[kind]) + r'/[^/]+',
                                values.get('id', ''), re.IGNORECASE):
                raise Blocked('owned SSH resource subscription/type mismatch')
        ip, username = pip.get('ip_address', ''), vm.get('admin_username', '')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', username) or not re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', ip) or any(int(part) > 255 for part in ip.split('.')):
            raise Blocked('unsafe owned SSH destination')
        if vm.get('network_interface_ids') != [nic['id']] or [c.get('public_ip_address_id') for c in nic.get('ip_configuration', [])] != [pip['id']]:
            raise Blocked('owned SSH VM/NIC/public IP association mismatch')
        guest = {'id': vm['id'], 'admin_username': username, 'public_ip': ip}
        if candidate is not None and any(candidate.get(k) != v for k, v in guest.items()):
            raise Blocked('SSH output/state identity mismatch')
        live = self.az('vm', 'show', '--ids', vm['id'], '--show-details')
        live_nics = [n.get('id') for n in live.get('networkProfile', {}).get('networkInterfaces', [])]
        if live.get('id', '').lower() != vm['id'].lower() or live.get('osProfile', {}).get('adminUsername') != username or live.get('publicIps') != ip or [n.lower() for n in live_nics] != [nic['id'].lower()]:
            raise Blocked('live ' + role + ' ownership/access mismatch')
        return guest

    def ssh_argv(self, guest, policy):
        return ['ssh', '-i', str(self.key), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=' + policy,
                '-o', 'UserKnownHostsFile=' + str(self.known_hosts),
                guest['admin_username'] + '@' + guest['public_ip']]

    def enroll_guest(self, guest):
        # Bound the authenticated no-op too, not only TCP connection establishment.
        original = self.deadline
        self.deadline = min(original, time.monotonic() + 20)
        try:
            self.run(self.ssh_argv(guest, 'accept-new') + ['true'])
        finally:
            self.deadline = original

    def enroll_guests(self):
        if not self.outputs or self.outputs.get('namespace') != self.scope['namespace'] or self.config['subscription_id'] != self.scope['subscription_id'] or self.config['namespace'] != self.scope['namespace']:
            raise Blocked('SSH enrollment scope mismatch')
        # Validate both destinations before contacting either; never trust output IPs alone.
        guests = [self.owned_guest(self.resources, role, self.outputs.get(role, {}))
                  for role in ('origin', 'generator')]
        for guest in guests:
            self.enroll_guest(guest)

    def cleanup_access(self, resources):
        """Partial-apply stop requires only an exactly state-owned live generator."""
        self.outputs = None
        if any(r.get('type') not in AZURE_TYPES | XC_TYPES or not r.get('address') or not r.get('values', {}).get('id') for r in resources):
            raise Blocked('cleanup ownership state incomplete')
        self.resources = resources
        if not any(r['type'] == 'azurerm_linux_virtual_machine' and r['address'].startswith('module.traffic_generator.') for r in resources):
            return
        guest = self.owned_guest(resources, 'generator')
        self.outputs = {'generator': guest}

    def traffic(self, action, cleanup=False):
        if not self.outputs:
            return
        original = self.deadline
        if cleanup:
            self.deadline = time.monotonic() + 20
        try:
            guest = self.owned_guest(self.resources, 'generator', self.outputs['generator'])
            self.enroll_guest(guest)
            self.run(self.ssh_argv(guest, 'yes') + ['sudo', '-n', '/usr/local/bin/tgen-control', action])
        finally:
            self.deadline = original
        self.phase('traffic-' + action)

    def verify_phase(self, phase):
        if phase != 'absence':
            self.enroll_guests()
        self.run(['bash', self.root / 'scripts/demo-verify.sh', '--outputs-json', self.state / 'outputs.json',
                  '--phase', phase, '--timeout-seconds', str(max(1, int(self.remaining()))),
                  '--report', self.state / (phase + '-report.json'), '--run-manifest', self.state / 'run-manifest.json',
                  '--ssh-key', self.key, '--known-hosts', self.known_hosts])
        self.phase('live-' + phase)

    def azure_api_versions(self, ids):
        """Use exact advertisements or confirm bounded ancestor candidates on each child."""
        result, catalogs, candidates = {}, {}, {}
        prefix = '/subscriptions/' + self.scope['subscription_id'].lower() + '/resourcegroups/'
        for rid in ids:
            if not isinstance(rid, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', rid) or '..' in rid or not rid.lower().startswith(prefix):
                raise Blocked('manifest Azure scope/identity mismatch')
            parts = rid.split('/providers/')
            if len(parts) == 1:
                if len(rid.split('/')) != 5:
                    raise Blocked('unknown Azure resource-group identity')
                namespace, resource_type = 'Microsoft.Resources', 'resourceGroups'
            else:
                tail = parts[-1].split('/')
                if len(tail) < 3 or len(tail) % 2 != 1:
                    raise Blocked('unknown Azure resource identity')
                namespace, resource_type = tail[0], '/'.join(tail[1::2])
            if namespace not in catalogs:
                catalogs[namespace] = self.az('provider', 'show', '--namespace', namespace).get('resourceTypes', [])
            matches = [r for r in catalogs[namespace] if r.get('resourceType', '').lower() == resource_type.lower()]
            versions = sorted({v for r in matches for v in r.get('apiVersions', []) if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', v)})
            if versions:
                result[rid] = versions[-1]
                continue
            # ARM omits some child types (notably virtualNetworks/subnets).
            # Ancestor advertisements are candidates, not evidence of child support.
            key = (namespace, resource_type)
            if key not in candidates:
                ancestor = resource_type
                candidates[key] = []
                while '/' in ancestor:
                    ancestor = ancestor.rsplit('/', 1)[0]
                    matches = [r for r in catalogs[namespace] if r.get('resourceType', '').lower() == ancestor.lower()]
                    versions = sorted({v for r in matches for v in r.get('apiVersions', [])
                                       if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', v)}, reverse=True)
                    if versions:
                        candidates[key] = versions[:3]
                        break
            if not candidates[key]:
                raise Blocked('no advertised stable ARM API version for ' + namespace + '/' + resource_type)
            for version in candidates[key][:]:
                try:
                    live = self.az('rest', '--method', 'get', '--url',
                                   'https://management.azure.com' + rid + '?api-version=' + version)
                except Blocked as exc:
                    # Only explicit unsupported-version failures permit another candidate.
                    # Absence, denied access and timeouts never become ownership proof.
                    if '(arm-api-version-unsupported)' in str(exc):
                        continue
                    raise
                if not isinstance(live, dict) or str(live.get('id', '')).lower() != rid.lower():
                    raise Blocked('ARM child live identity mismatch')
                properties = live.get('properties')
                if not isinstance(properties, dict) or properties.get('provisioningState') != 'Succeeded':
                    raise Blocked('ARM child provisioning state unavailable/not Succeeded')
                result[rid] = version
                candidates[key].remove(version)
                candidates[key].insert(0, version)
                break
            else:
                raise Blocked('no confirmed stable ARM API version for ' + namespace + '/' + resource_type)
        return result

    def foundation_proof(self):
        """Join existing receipts, provider state and live UID without writing any ledger."""
        persistent = {'namespace': 'system/' + self.scope['namespace']}
        identity = private_json(self.state / 'namespace-receipt.json')
        raw = private_json(self.state / 'namespace.tfstate')
        resources = raw.get('resources', [])
        if (private_json(self.state / 'persistent.json') != persistent
                or len(resources) != 1 or resources[0].get('mode') != 'managed'
                or resources[0].get('type') != 'xcsh_namespace'
                or resources[0].get('name') != 'this' or resources[0].get('module')
                or len(resources[0].get('instances', [])) != 1):
            raise Blocked('foundation provider state/receipt mismatch')
        attrs = resources[0]['instances'][0].get('attributes', {})
        live = self.xc('/api/web/namespaces/' + self.scope['namespace'])
        uid = live.get('system_metadata', {}).get('uid')
        expected = {'path': '/api/web/namespaces/' + self.scope['namespace'], 'uid': uid}
        if (not uid or identity != expected
                or attrs.get('name') != self.scope['namespace'] or attrs.get('id') != self.scope['namespace']
                or live.get('metadata', {}).get('name') != self.scope['namespace']
                or self.namespace_uid not in (None, uid)):
            raise Blocked('foundation namespace UID identity mismatch')
        return persistent, uid

    def recover_manifest(self):
        """Repair only the known empty-foundation writer defect; never adopt resources."""
        import hashlib
        manifest = self.state / 'run-manifest.json'
        previous = private_json(manifest)
        snapshot = manifest.read_bytes()
        keys = {'schema_version', 'namespace', 'subscription_id', 'owned_resources',
                'azure_owned', 'xc_owned', 'azure_preserved', 'xc_preserved',
                'persistent_resource_ids', 'azure_api_versions'}
        if (not isinstance(previous, dict) or set(previous) != keys
                or previous.get('persistent_resource_ids') != {}
                or previous.get('azure_preserved') != []):
            raise Blocked('not the known empty-foundation manifest corruption')
        self.local_backend_check()
        persistent, uid = self.foundation_proof()
        if previous.get('xc_preserved') != [{'path': '/api/web/namespaces/' + self.scope['namespace'], 'uid': uid}]:
            raise Blocked('corrupt manifest prior namespace UID mismatch')
        self.persistent, self.namespace_uid = persistent, uid
        owned = self.inventory(persist=False)
        expected = dict(previous, persistent_resource_ids=persistent)
        if self.inventory_receipt != expected:
            raise Blocked('corrupt manifest resource identity ledger mismatch')
        for rid, version in previous['azure_api_versions'].items():
            live = self.az('rest', '--method', 'get', '--url',
                           'https://management.azure.com' + rid + '?api-version=' + version)
            if not isinstance(live, dict) or str(live.get('id', '')).lower() != rid.lower():
                raise Blocked('corrupt manifest live Azure identity mismatch')
        self.guard_group_children(self.resources)
        self.verify_fixture()
        if manifest.read_bytes() != snapshot:
            raise Blocked('manifest changed during recovery')
        digest = hashlib.sha256(snapshot).hexdigest()
        backup = manifest.with_name('run-manifest.corrupt-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + digest + '.json')
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(snapshot)
            stream.flush()
            os.fsync(stream.fileno())
        save_json(manifest, self.inventory_receipt)
        return {'backup': str(backup), 'sha256': digest, 'namespace_uid': uid, 'owned_count': len(owned)}

    def inventory(self, persist=True):
        if self.persistent != {'namespace': 'system/' + self.scope['namespace']} or not self.namespace_uid:
            raise Blocked('inventory foundation not initialized; explicit external migration required')
        self.foundation_proof()
        manifest = self.state / 'run-manifest.json'
        if persist and manifest.exists():
            prior = private_json(manifest)
            if (prior.get('persistent_resource_ids') != self.persistent or prior.get('azure_preserved') != []
                    or prior.get('xc_preserved') != [{'path': '/api/web/namespaces/' + self.scope['namespace'], 'uid': self.namespace_uid}]):
                raise Blocked('existing run foundation incompatible; explicit external migration required')
        value = json.loads(self.tf(self.app, 'show', '-json')[0])
        resources = list(managed_resources(value.get('values', {}).get('root_module', {})))
        if not resources:
            raise Blocked('missing application state/resources; refusing unowned operation')
        for item in resources:
            if item['type'] == 'xcsh_namespace':
                raise Blocked('namespace owned by application state; explicit external migration required')
            if item['type'] not in AZURE_TYPES | XC_TYPES or not item['values'].get('id'):
                raise Blocked('protected/unknown ownership in application state')
            if item['values']['id'] in self.persistent.values():
                raise Blocked('persistent resource present in application state')
        if self.operation in ('destroy', 'rebuild'):
            self.guard_group_children(resources)
        self.resources = resources
        xc_owned = []
        for item in resources:
            if item['type'] not in XC_TYPES:
                continue
            collection = XC_COLLECTIONS.get(item['type'])
            name = item['values'].get('name')
            namespace = item['values'].get('namespace')
            if not collection or namespace != self.scope['namespace'] or not re.fullmatch(r'[a-z][a-z0-9-]*[a-z0-9]', name or ''):
                raise Blocked('missing catalog-backed XC ownership identity')
            path = '/api/config/namespaces/' + namespace + '/' + collection + '/' + name
            live = self.xc(path)
            uid = live.get('system_metadata', {}).get('uid')
            if not uid or live.get('metadata', {}).get('name') != name:
                raise Blocked('live XC ownership identity unavailable')
            xc_owned.append({'path': path, 'uid': uid})
        namespace = self.xc('/api/web/namespaces/' + self.scope['namespace'])
        namespace_uid = namespace.get('system_metadata', {}).get('uid')
        if not namespace_uid or (self.namespace_uid and namespace_uid != self.namespace_uid):
            raise Blocked('persistent namespace UID missing or changed')
        receipt = {'schema_version': 1, 'namespace': self.scope['namespace'], 'subscription_id': self.scope['subscription_id'],
                   'owned_resources': [{'address': r['address'], 'type': r['type'], 'id': r['values']['id']} for r in resources],
                   'azure_owned': sorted(set(r['values']['id'].split('|')[0] for r in resources if r['type'] in AZURE_TYPES)),
                   'xc_owned': xc_owned,
                   'azure_preserved': [],
                   'xc_preserved': [{'path': '/api/web/namespaces/' + self.scope['namespace'], 'uid': namespace_uid}],
                   'persistent_resource_ids': self.persistent}
        receipt['azure_api_versions'] = self.azure_api_versions(receipt['azure_owned'] + receipt['azure_preserved'])
        self.inventory_receipt = receipt
        if persist:
            save_json(self.state / 'run-manifest.json', receipt)
        return {r['address']: r['values']['id'] for r in resources}

    def verify_fixture(self):
        """Read back the pinned fixture through the canonical upload verifier, GET only."""
        receipt_path = self.state / 'swagger-receipt.json'
        if not receipt_path.is_file() or receipt_path.is_symlink():
            raise Blocked('fixture preservation receipt missing')
        saved = json.loads(receipt_path.read_text())
        pinned = json.loads(self.vars.read_text()).get('api_definition_swagger_specs')
        if saved.get('api_url') != self.scope['xc_url'] or saved.get('namespace') != self.scope['namespace'] or saved.get('name') != 'showcase' or pinned != [saved.get('path')] or not isinstance(saved.get('content'), str):
            raise Blocked('fixture preservation identity mismatch')
        spec = importlib.util.spec_from_file_location('showcase_swagger_upload', self.root / 'scripts/swagger_upload.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        owner = self
        class ReadOnlyClient:
            def request(self, method, path):
                if method != 'GET' or path != saved['path']:
                    raise Blocked('fixture verification must remain read-only')
                return owner.xc(path)
        try:
            version = helper.version(saved.get('version'))
            expected = '/api/object_store/namespaces/' + self.scope['namespace'] + '/stored_objects/swagger/showcase/' + version
            if expected != saved.get('path'):
                raise Blocked('fixture preservation path mismatch')
            helper.verify(ReadOnlyClient(), expected, 'showcase', self.scope['namespace'], version, saved['content'])
        except helper.UploadError as exc:
            raise Blocked('fixture preservation content/version verification failed') from exc

    def deploy(self):
        self.namespace_tf_prepare(create=True)
        self.app_init()
        upload_env = dict(self.env, SWAGGER_RECEIPT_PATH=str(self.state / 'swagger-receipt.json'))
        pinned = self.run(['bash', self.root / 'scripts/swagger-upload.sh', 'showcase', self.app / 'fixtures/showcase-openapi.json', self.scope['namespace']], env=upload_env)[0].strip()
        if not re.fullmatch(r'/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/[A-Za-z0-9][A-Za-z0-9._-]*', pinned) or pinned.endswith('/latest'):
            raise Blocked('upload did not return exact versioned object path')
        profile = json.loads((self.app / 'showcase.tfvars.json').read_text())
        profile.update(namespace=self.scope['namespace'], subscription_id=self.scope['subscription_id'], lb_domains=self.scope['domains'],
                       ssh_public_key_path=str(self.key) + '.pub', api_definition_swagger_specs=[pinned])
        save_json(self.vars, profile)
        self.phase('pinned-schema-upload')
        plan = self.plan('application')
        self.tf(self.app, 'apply', '-input=false', str(plan))
        self.get_outputs()
        self.inventory()
        self.verify_phase('readiness')
        self.traffic('start')
        self.verify_phase('acceptance')
        noop = self.plan('post-acceptance-drift', 'noop')
        self.tf(self.app, 'apply', '-input=false', str(noop))
        self.phase('zero-change-apply')

    def verify(self):
        self.namespace_tf_prepare()
        self.app_init()
        if not self.vars.is_file():
            raise Blocked('missing secure deployed variable receipt')
        self.get_outputs()
        self.inventory()
        self.verify_phase('readiness')
        self.verify_phase('acceptance')
        self.plan('verify-drift', 'noop')

    def destroy(self):
        self.namespace_tf_prepare()
        self.app_init()
        if not self.vars.is_file():
            raise Blocked('missing secure deployed variable receipt')
        owned = self.inventory()
        self.cleanup_access(self.resources)
        self.traffic('stop')
        plan = self.plan('destroy', 'destroy', owned)
        self.tf(self.app, 'apply', '-input=false', str(plan))
        remaining = json.loads(self.tf(self.app, 'show', '-json')[0])
        if list(managed_resources(remaining.get('values', {}).get('root_module', {}))):
            raise Blocked('application state remains populated after destroy')
        self.verify_phase('absence')
        self.namespace_tf_prepare()
        self.verify_fixture()
        self.phase('schema-fixture-survives')
        self.phase('persistent-resources-survive')
        self.outputs = None

    def execute(self):
        lock_path = self.state / 'lifecycle.lock'
        secure_artifact(lock_path)
        with lock_path.open('a') as lock:
            lock_path.chmod(0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Blocked('another lifecycle operation holds the subscription lock') from None
            try:
                self.preflight(self.operation in ('deploy', 'rebuild'))
                if self.operation == 'rebuild':
                    self.destroy()
                    self.deploy()
                else:
                    getattr(self, self.operation)()
                self.receipt['status'] = 'verified'
                self.phase('complete')
            except BaseException as exc:
                self.receipt['status'] = 'blocked'
                self.receipt['error'] = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
                try:
                    if self.outputs is None and self.app_ready:
                        old_deadline = self.deadline
                        self.deadline = time.monotonic() + 15
                        try:
                            value = json.loads(self.tf(self.app, 'show', '-json')[0])
                            resources = list(managed_resources(value.get('values', {}).get('root_module', {})))
                            if not resources or any(not r.get('values', {}).get('id') for r in resources):
                                raise Blocked('cleanup ownership state unavailable')
                            self.cleanup_access(resources)
                        finally:
                            self.deadline = old_deadline
                    self.traffic('stop', cleanup=True)
                except BaseException:
                    self.receipt['cleanup'] = 'traffic stop failed or unreachable; original failure retained'
                self.phase('failure', 'blocked')
                raise
            finally:
                for path in self.state.rglob('*'):
                    secure_artifact(path, private=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('deploy', 'verify', 'rebuild', 'destroy'))
    parser.add_argument('--config', type=Path, help='private external JSON instead of ~/.local/state/waap-showcase/operator.json; approved Azure IDs required')
    parser.add_argument('--state-dir', type=Path, help='private persistent directory outside checkout')
    parser.add_argument('--timeout-seconds', type=int, default=1800)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1:
        parser.error('--timeout-seconds must be positive')
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        Lifecycle(args).execute()
    except (Blocked, OSError, ValueError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        message = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
        print('[blocked] ' + message + '; preserve state and inspect private operation-receipt.json', file=sys.stderr)
        return 1
    print('Lifecycle verified; private receipts contain live evidence, not Terraform acceptance alone.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
