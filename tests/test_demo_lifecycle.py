"""Failure-path tests; these are not live security acceptance evidence."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
import json
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('demo_lifecycle', Path(__file__).resolve().parents[1] / 'scripts/demo_lifecycle.py')
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)

TEST_APPROVAL = {'subscription_id': '00000000-0000-0000-0000-000000000000',
                 'tenant_id': '11111111-1111-1111-1111-111111111111'}
TEST_SCOPE = dict(lifecycle.FIXED, **TEST_APPROVAL)


class TerraformWiring(unittest.TestCase):
    def test_generator_identity_is_not_deferred_by_load_balancer(self):
        import hcl2
        root = Path(__file__).resolve().parents[1]
        config = hcl2.loads((root / 'terraform/main.tf').read_text())
        modules = {name: values for block in config['module'] for name, values in block.items()}
        generator = modules['traffic_generator']
        self.assertNotIn('depends_on', generator)
        def expression(module, key):
            value = module[key]
            return value[0] if isinstance(value, list) else value
        self.assertEqual(expression(generator, 'deployer'), '${var.deployer}')
        self.assertEqual(expression(generator, 'component'), 'traffic-generator')
        self.assertIn('module.origin_server.public_ip', expression(generator, 'custom_data'))
        self.assertIn('jsonencode(var.lb_domains)', expression(generator, 'custom_data'))
        self.assertEqual(expression(modules['http_lb'], 'origin_ip'), '${module.origin_server.public_ip}')

    def test_showcase_profile_renders_complete_mixed_targets(self):
        import hcl2
        from collections import Counter
        from urllib.parse import urlsplit
        root = Path(__file__).resolve().parents[1]
        profile = json.loads((root / 'terraform/showcase.tfvars.json').read_text())
        config = hcl2.loads((root / 'terraform/main.tf').read_text())
        modules = {name: values for block in config['module'] for name, values in block.items()}
        rendered = modules['traffic_generator']['custom_data']
        self.assertIn('templatefile("${path.module}/cloud-init/traffic-generator.yaml"', rendered)
        self.assertIn('"target_domains": "${jsonencode(var.lb_domains)}"', rendered)
        self.assertIn('"mud_bad_traffic": "${var.mud_enabled && var.mud_bad_traffic}"', rendered)
        # Parse this scalar declaration without unrelated multi-line validations.
        declaration = 'variable "mud_bad_traffic" {' + (root / 'terraform/variables.tf').read_text().split('variable "mud_bad_traffic" {', 1)[1].split('}', 1)[0] + '}'
        variables = hcl2.loads(declaration)
        defaults = {name: value.get('default') for block in variables['variable'] for name, value in block.items()}
        self.assertIs(defaults['mud_bad_traffic'], False)
        self.assertIs(profile['mud_enabled'], True)
        self.assertIs(profile.get('mud_bad_traffic', defaults['mud_bad_traffic']), True)
        # Evaluate the exact asserted root expression, then render its guest config.
        effective_mud = profile['mud_enabled'] and profile.get('mud_bad_traffic', defaults['mud_bad_traffic'])
        template = (root / 'terraform/cloud-init/traffic-generator.yaml').read_text()
        config_line = next(line.strip() for line in template.splitlines() if line.strip().startswith('{"target_domains":'))
        replacements = {'target_domains': json.dumps(profile['lb_domains']),
                        'target_origin_ip': '192.0.2.1', 'tool_tier': 'core',
                        'mud_bad_traffic': json.dumps(effective_mud)}
        for key, value in replacements.items():
            config_line = config_line.replace('${' + key + '}', value)
        guest = json.loads(config_line)
        spec = importlib.util.spec_from_file_location('profile_demo_traffic', root / 'scripts/demo_traffic.py')
        traffic = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(traffic)
        generated = traffic.targets(guest['target_domains'], 'profile-regression', 0, guest['mud_bad_traffic'])
        counts = Counter((urlsplit(target['url']).hostname, target['header']['X-Demo-Class'][0]) for target in generated)
        self.assertEqual(len(generated), 1500)
        expected = {'benign': 675, 'waf': 15, 'schema': 10,
                    'endpoint-denial': 10, 'rate-limit': 25, 'mud': 15}
        for domain in profile['lb_domains']:
            for cls, count in expected.items():
                self.assertEqual(counts[(domain, cls)], count)
            self.assertEqual(sum(counts[(domain, cls)] for cls in expected), 750)
        self.assertEqual(len(counts), 12)
        for enabled, bad in ((False, True), (True, False), (False, False)):
            with self.subTest(mud_enabled=enabled, mud_bad_traffic=bad):
                with self.assertRaisesRegex(ValueError, 'showcase requires mud_bad_traffic'):
                    traffic.targets(guest['target_domains'], 'disabled-regression', 0, enabled and bad)


class OperatorAuthorization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'checkout'
        self.root.mkdir()
        self.args = SimpleNamespace(operation='deploy', config=None,
                                    state_dir=self.base / 'state', timeout_seconds=30)
        environment = {key: value for key, value in lifecycle.os.environ.items()
                       if not key.startswith('DEMO_AZURE_')}
        environment.update(DEMO_AZURE_SUBSCRIPTION_ID=TEST_APPROVAL['subscription_id'],
                           DEMO_AZURE_TENANT_ID=TEST_APPROVAL['tenant_id'])
        self.home = self.base / 'home'
        self.operator_base = self.home / '.local/state/waap-showcase'
        home_patch = patch.object(lifecycle.Path, 'home', return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)
        self.environment = patch.dict(lifecycle.os.environ, environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def config_file(self, name='operator.json', value=None):
        self.args.state_dir.mkdir(mode=0o700, exist_ok=True)
        self.operator_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.operator_base / name
        lifecycle.save_json(path, dict(TEST_APPROVAL, **(value if value is not None else
                            {'expected_azure_user': 'operator@example.test'})))
        return path

    def instance(self):
        return lifecycle.Lifecycle(self.args, self.root)

    def preflight_instance(self, authorized=True):
        if authorized:
            self.config_file()
        obj = self.instance()
        for relative in ('scripts/demo-verify.sh', 'scripts/swagger-upload.sh',
                         'terraform/showcase.tfvars.json', 'terraform/fixtures/showcase-openapi.json'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        obj.key = self.base / 'key'
        obj.key.write_text('synthetic')
        obj.key.chmod(0o600)
        obj.key.with_name('key.pub').write_text('ssh-ed25519 synthetic')
        obj.env.update(XCSH_API_URL=lifecycle.FIXED['xc_url'], XCSH_API_TOKEN='synthetic')
        obj.local_backend_check = Mock()
        obj.run = Mock(side_effect=[('ssh-ed25519 synthetic', 0),
                                    ('ns.example.test hostmaster.example.test 1 2 3 4 5', 0)])
        obj.az = Mock(return_value={'id': TEST_SCOPE['subscription_id'],
                                    'tenantId': TEST_SCOPE['tenant_id'], 'state': 'Enabled',
                                    'user': {'type': 'user', 'name': 'OPERATOR@EXAMPLE.TEST'}})
        obj.namespace_prepare = Mock()
        obj.xc = Mock(return_value={'state': 'AS_SUBSCRIBED'})
        obj.capacity_permissions = Mock()
        return obj

    def test_default_private_operator_file(self):
        path = self.config_file()
        obj = self.instance()
        self.assertEqual(obj.config['expected_azure_user'], 'operator@example.test')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(obj.state.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('expected_azure_user', obj.receipt['scope'])

    def test_explicit_config_replaces_default_without_merge(self):
        self.config_file(value={'expected_azure_user': 'other@example.test', 'ssh_key': '/unused'})
        self.args.config = self.config_file('explicit.json')
        obj = self.instance()
        self.assertEqual(obj.config['expected_azure_user'], 'operator@example.test')
        self.assertNotEqual(str(obj.key), '/unused')

    def test_config_overrides_environment(self):
        self.config_file()
        with patch.dict(lifecycle.os.environ, {'DEMO_AZURE_USER': 'env@example.test'}):
            self.assertEqual(self.instance().config['expected_azure_user'], 'operator@example.test')

    def test_environment_only_when_chosen_config_omits_user(self):
        self.config_file(value={'expected_azure_user': 'other@example.test'})
        self.args.config = self.config_file('explicit.json', {})
        with patch.dict(lifecycle.os.environ, {'DEMO_AZURE_USER': 'env@example.test'}):
            self.assertEqual(self.instance().config['expected_azure_user'], 'env@example.test')
        self.assertNotIn('expected_azure_user', self.instance().config)

    def test_environment_without_operator_file(self):
        with patch.dict(lifecycle.os.environ, {'DEMO_AZURE_USER': 'env@example.test'}):
            self.assertEqual(self.instance().config['expected_azure_user'], 'env@example.test')

    def test_approved_ids_override_environment_without_global_mutation(self):
        path = self.config_file()
        before = dict(lifecycle.FIXED)
        with patch.dict(lifecycle.os.environ, {
                'DEMO_AZURE_SUBSCRIPTION_ID': TEST_APPROVAL['tenant_id'],
                'DEMO_AZURE_TENANT_ID': TEST_APPROVAL['subscription_id']}):
            first = self.instance()
        self.args.config = self.config_file('other.json', {
            'subscription_id': TEST_APPROVAL['tenant_id'],
            'tenant_id': TEST_APPROVAL['subscription_id']})
        second = self.instance()
        self.assertEqual(first.scope, TEST_SCOPE)
        self.assertEqual(second.scope['subscription_id'], TEST_APPROVAL['tenant_id'])
        self.assertEqual(lifecycle.FIXED, before)
        self.assertNotIn('subscription_id', lifecycle.FIXED)
        self.assertEqual(first.env['ARM_SUBSCRIPTION_ID'], TEST_APPROVAL['subscription_id'])
        self.assertEqual(first.env['ARM_TENANT_ID'], TEST_APPROVAL['tenant_id'])
        self.assertEqual(first.receipt['scope'], TEST_SCOPE)
        self.assertNotIn('expected_azure_user', first.receipt['scope'])
        self.assertEqual(path.parent, self.operator_base)

    def test_chosen_config_missing_ids_uses_explicit_environment_only(self):
        self.config_file()
        explicit = self.config_file('empty.json')
        lifecycle.save_json(explicit, {})
        self.args.config = explicit
        with patch.dict(lifecycle.os.environ, {
                'DEMO_AZURE_SUBSCRIPTION_ID': TEST_APPROVAL['tenant_id'],
                'DEMO_AZURE_TENANT_ID': TEST_APPROVAL['subscription_id']}):
            obj = self.instance()
        self.assertEqual(obj.scope['subscription_id'], TEST_APPROVAL['tenant_id'])
        self.assertNotIn('expected_azure_user', obj.config)

    def test_missing_ids_block_before_state_creation_or_identity_probe(self):
        for missing in ('DEMO_AZURE_SUBSCRIPTION_ID', 'DEMO_AZURE_TENANT_ID'):
            environment = dict(lifecycle.os.environ)
            environment.pop(missing)
            with self.subTest(missing=missing), patch.dict(lifecycle.os.environ, environment, clear=True):
                with patch.object(lifecycle.Lifecycle, 'az') as az:
                    with self.assertRaisesRegex(lifecycle.Blocked, 'approved Azure .* missing'):
                        self.instance()
                    az.assert_not_called()
                self.assertFalse(self.args.state_dir.exists())

    def test_malformed_ids_rejected_without_echoing_input(self):
        for key in TEST_APPROVAL:
            for invalid in (None, True, {}, [], '', 'private-malformed-value',
                            TEST_APPROVAL[key] + '\n', '{' + TEST_APPROVAL[key] + '}'):
                with self.subTest(key=key, invalid=invalid):
                    with self.assertRaisesRegex(lifecycle.Blocked, 'canonical UUID') as error:
                        lifecycle.config_values(dict(TEST_APPROVAL, **{key: invalid}))
                    self.assertNotIn('private-malformed-value', str(error.exception))

    def test_existing_receipts_reject_changed_approved_scope(self):
        obj = self.instance()
        for filename, value in (('operation-receipt.json', {'scope': {
                'subscription_id': TEST_APPROVAL['tenant_id'], 'tenant_id': TEST_APPROVAL['tenant_id']}}),
                ('run-manifest.json', {'subscription_id': TEST_APPROVAL['tenant_id']})):
            with self.subTest(filename=filename):
                path = obj.state / filename
                lifecycle.save_json(path, value)
                with self.assertRaisesRegex(lifecycle.Blocked, 'explicit external migration'):
                    self.instance()
                path.unlink()

    def test_default_approval_does_not_follow_state_dir(self):
        self.args.state_dir.mkdir(mode=0o700)
        lifecycle.save_json(self.args.state_dir / 'operator.json', dict(
            TEST_APPROVAL, expected_azure_user='foreign@example.test'))
        obj = self.instance()
        self.assertNotIn('expected_azure_user', obj.config)

    def test_cli_help_requires_no_approval(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/demo_lifecycle.py'
        environment = {k: v for k, v in lifecycle.os.environ.items() if not k.startswith('DEMO_AZURE_')}
        result = subprocess.run([sys.executable, str(script), '--help'], env=environment,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn('operator.json; approved Azure IDs required', result.stdout)


    def test_invalid_authorized_upns_do_not_leak_values(self):
        for value in (None, True, {}, [], '', 'no-at-sign', '@example.test',
                      'operator@', 'operator@@example.test', 'operator@example.test\n',
                      'operator @example.test',
                      'operator\x00@example.test', 'öperator@example.test',
                      'a' * 309 + '@example.test'):
            with self.subTest(value=value), self.assertRaisesRegex(lifecycle.Blocked, 'bounded printable UPN'):
                lifecycle.config_values({'expected_azure_user': value})
        with patch.dict(lifecycle.os.environ, {'DEMO_AZURE_USER': ''}):
            with self.assertRaisesRegex(lifecycle.Blocked, 'bounded printable UPN'):
                self.instance()
        guest = 'operator_example.test#EXT#@tenant.example.test'
        self.assertEqual(lifecycle.config_values({'expected_azure_user': guest})['expected_azure_user'], guest)

    def test_unsafe_file_permissions_and_symlinks_rejected(self):
        path = self.config_file()
        path.chmod(0o644)
        with self.assertRaisesRegex(lifecycle.Blocked, 'mode 0600'):
            self.instance()
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        path.chmod(0o600)
        link = self.args.state_dir / 'link.json'
        link.symlink_to(path)
        self.args.config = link
        with self.assertRaisesRegex(lifecycle.Blocked, 'symlinks'):
            self.instance()

    def test_broken_default_symlink_rejected(self):
        self.operator_base.mkdir(parents=True)
        (self.operator_base / 'operator.json').symlink_to(self.base / 'absent')
        with self.assertRaisesRegex(lifecycle.Blocked, 'symlinks'):
            self.instance()

    def test_config_checkout_scope_missing_and_malformed_rejected(self):
        self.args.config = self.root / 'operator.json'
        lifecycle.save_json(self.args.config, {})
        with self.assertRaisesRegex(lifecycle.Blocked, 'outside the checkout'):
            self.instance()
        self.args.config = self.base / 'absent.json'
        with self.assertRaisesRegex(lifecycle.Blocked, 'existing private'):
            self.instance()
        self.args.config = self.config_file()
        self.args.config.write_text('{malformed')
        with self.assertRaisesRegex(lifecycle.Blocked, 'JSON artifact unreadable'):
            self.instance()

    def test_foreign_owner_parent_symlink_and_directory_rejected(self):
        path = self.config_file()
        with patch.object(lifecycle.os, 'getuid', return_value=path.stat().st_uid + 1):
            with self.assertRaisesRegex(lifecycle.Blocked, 'ownership/type'):
                lifecycle.operator_config(path, self.root)
        link = self.base / 'linked-state'
        link.symlink_to(self.args.state_dir, target_is_directory=True)
        with self.assertRaisesRegex(lifecycle.Blocked, 'symlinks'):
            lifecycle.operator_config(link / 'operator.json', self.root)
        with self.assertRaisesRegex(lifecycle.Blocked, 'existing private'):
            lifecycle.operator_config(self.args.state_dir, self.root)

    def test_default_home_profile_without_state_argument(self):
        self.args.state_dir = None
        home = self.base / 'home'
        state = home / '.local/state/waap-showcase' / TEST_SCOPE['subscription_id']
        state.mkdir(parents=True, mode=0o700)
        lifecycle.save_json(state.parent / 'operator.json', dict(TEST_APPROVAL, expected_azure_user='operator@example.test'))
        with patch.object(lifecycle.Path, 'home', return_value=home):
            obj = self.instance()
        self.assertEqual(obj.state, state)
        self.assertEqual(obj.config['expected_azure_user'], 'operator@example.test')

    def test_operator_config_preserves_fixed_scope_restrictions(self):
        for key in lifecycle.FIXED:
            with self.subTest(key=key):
                self.config_file(value={key: 'other', 'expected_azure_user': 'operator@example.test'})
                with self.assertRaisesRegex(lifecycle.Blocked, 'fixed identity/scope override'):
                    self.instance()


    def test_missing_authorization_never_infers_current_user(self):
        obj = self.preflight_instance(authorized=False)
        with patch.object(lifecycle.shutil, 'which', return_value='/synthetic/tool'):
            with self.assertRaisesRegex(lifecycle.Blocked, 'authorized Azure user missing'):
                obj.preflight(True)
        obj.az.assert_not_called()
        obj.namespace_prepare.assert_not_called()
        obj.capacity_permissions.assert_not_called()

    def test_casefold_exact_approved_human_passes(self):
        obj = self.preflight_instance()
        with patch.object(lifecycle.shutil, 'which', return_value='/synthetic/tool'):
            obj.preflight(True)
        obj.capacity_permissions.assert_called_once()
        self.assertNotIn('operator@example.test', json.dumps(obj.receipt).lower())

    def test_wrong_human_type_subscription_tenant_or_state_blocks(self):
        for field, value in (('name', 'another@example.test'), ('name', None),
                             ('type', 'servicePrincipal'), ('id', 'other'),
                             ('tenantId', 'other'), ('state', 'Disabled')):
            with self.subTest(field=field, value=value):
                obj = self.preflight_instance()
                account = obj.az.return_value
                (account['user'] if field in ('name', 'type') else account)[field] = value
                with patch.object(lifecycle.shutil, 'which', return_value='/synthetic/tool'):
                    with self.assertRaises(lifecycle.Blocked) as caught:
                        obj.preflight(True)
                self.assertNotIn('@', str(caught.exception))
                obj.namespace_prepare.assert_not_called()
                obj.capacity_permissions.assert_not_called()



class Guards(unittest.TestCase):
    def test_identity_override_rejected(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.config_values({'subscription_id': 'other'})

    def test_unknown_config_rejected(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.config_values({'command': '$(touch /tmp/unsafe)'})

    def test_fixed_config_accepted(self):
        self.assertEqual(lifecycle.config_values(TEST_APPROVAL)['namespace'], 'webapp-api-protection')

    def test_noop_guard_rejects_change(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan({'resource_changes': [{'mode': 'managed', 'type': 'azurerm_linux_virtual_machine', 'change': {'actions': ['update']}}]}, 'noop')

    def test_destroy_rejects_namespace(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan({'resource_changes': [{'mode': 'managed', 'type': 'xcsh_namespace', 'change': {'actions': ['delete']}}]}, 'destroy')

    def test_deploy_rejects_even_unchanged_namespace_ownership(self):
        with self.assertRaisesRegex(lifecycle.Blocked, 'explicit external migration'):
            lifecycle.guard_plan({'resource_changes': [{'mode': 'managed', 'type': 'xcsh_namespace',
                                  'change': {'actions': ['no-op']}}]}, 'deploy')

    def test_destroy_rejects_create(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan({'resource_changes': [{'mode': 'managed', 'type': 'azurerm_linux_virtual_machine', 'change': {'actions': ['create']}}]}, 'destroy')

    def test_noop_output_drift_rejected(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan({'output_changes': {'showcase': {'actions': ['update']}}}, 'noop')

    def test_state_dir_inside_checkout_rejected(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.secure_directory(Path(__file__).resolve().parents[1] / 'unsafe-state', Path(__file__).resolve().parents[1])

    def test_private_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            lifecycle.save_json(path, {'phase': 'test'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unknown_destroy_type_rejected(self):
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan({'resource_changes': [{'mode': 'managed', 'type': 'xcsh_dns_zone', 'change': {'actions': ['delete']}}]}, 'destroy')


class LocalBackend(unittest.TestCase):
    setUp = lambda self: Orchestration.setUp(self)

    def prepare_namespace(self):
        obj = self.instance
        obj.az = Mock(side_effect=AssertionError('namespace/local backend must not call Azure'))
        obj.xc = Mock(return_value={'metadata': {'name': lifecycle.FIXED['namespace']}, 'system_metadata': {'uid': 'namespace-uid'}})
        obj.tf = Mock()
        return obj

    def test_namespace_readonly_and_local_path(self):
        obj = self.prepare_namespace()
        obj.namespace_prepare()
        self.assertEqual(obj.persistent, {'namespace': 'system/' + lifecycle.FIXED['namespace']})
        self.assertEqual(obj.namespace_uid, 'namespace-uid')
        self.assertEqual(obj.backend, {'path': str(obj.state / 'application.tfstate')})
        obj.az.assert_not_called()
        obj.tf.assert_not_called()

    def test_missing_namespace_never_created(self):
        obj = self.prepare_namespace()
        obj.xc.return_value = None
        with self.assertRaisesRegex(lifecycle.Blocked, 'namespace missing'):
            obj.namespace_prepare()
        obj.xc.assert_called_once_with('/api/web/namespaces/webapp-api-protection', allow_absent=True)

    def test_old_receipts_require_explicit_migration(self):
        obj = self.prepare_namespace()
        for filename, value in (('persistent.json', {'namespace': 'system/' + lifecycle.FIXED['namespace'], 'storage_account': 'old'}),
                                ('run-manifest.json', {'persistent_resource_ids': obj.persistent, 'azure_preserved': ['old']})):
            with self.subTest(filename=filename):
                path = obj.state / filename
                lifecycle.save_json(path, value)
                with self.assertRaisesRegex(lifecycle.Blocked, 'explicit external migration'):
                    obj.namespace_prepare()
                path.unlink()
        obj.xc.assert_not_called()

    def test_namespace_uid_change_blocks(self):
        obj = self.prepare_namespace()
        obj.namespace_prepare()
        obj.xc.return_value['system_metadata']['uid'] = 'different'
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID changed'):
            obj.namespace_prepare()
        obj.namespace_uid = None  # New invocation must retain the previously observed UID.
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID changed'):
            obj.namespace_prepare()

    def test_checkout_state_never_transferred(self):
        obj = self.prepare_namespace()
        (obj.app / 'terraform.tfstate').write_text('existing state')
        with self.assertRaisesRegex(lifecycle.Blocked, 'explicit migration'):
            obj.app_init()
        self.assertEqual((obj.app / 'terraform.tfstate').read_text(), 'existing state')
        obj.tf.assert_not_called()

    def test_namespace_in_application_state_requires_migration(self):
        obj = self.instance
        obj.tf = Mock(return_value=(json.dumps({'values': {'root_module': {'resources': [
            {'mode': 'managed', 'type': 'xcsh_namespace', 'values': {'id': 'system/webapp-api-protection'}}]}}}), 0))
        with self.assertRaisesRegex(lifecycle.Blocked, 'explicit external migration'):
            obj.inventory()

    def test_backend_config_always_rejected(self):
        for backend in ({}, {'path': '/tmp/state'}, {'access_key': 'secret'}, {'storage_account_name': 'otheraccount123'}):
            with self.subTest(backend=backend), self.assertRaisesRegex(lifecycle.Blocked, '--state-dir'):
                lifecycle.config_values({'backend': backend})

    def test_remote_and_alternate_initialized_backend_fail_before_init(self):
        obj = self.prepare_namespace()
        data = obj.state / 'application-data'
        data.mkdir()
        for kind, config in (('azurerm', {}), ('local', {'path': '/tmp/other.tfstate'}),
                             ('local', {'path': obj.backend['path'], 'workspace_dir': '/tmp/workspaces'})):
            with self.subTest(kind=kind, config=config):
                lifecycle.save_json(data / 'terraform.tfstate', {'backend': {'type': kind, 'config': config}})
                with self.assertRaisesRegex(lifecycle.Blocked, 'explicit migration'):
                    obj.app_init()
        obj.tf.assert_not_called()

    def test_empty_uninitialized_generated_config_can_be_replaced(self):
        obj = self.prepare_namespace()
        lifecycle.save_json(obj.state / 'backend.json', {'storage_account_name': 'old'})
        obj.app_init()
        self.assertEqual(json.loads((obj.state / 'backend.json').read_text()), obj.backend)

    def test_old_generated_config_with_state_is_not_replaced(self):
        obj = self.prepare_namespace()
        lifecycle.save_json(obj.state / 'backend.json', {'storage_account_name': 'old'})
        lifecycle.save_json(obj.state / 'application.tfstate', {'version': 4, 'resources': []})
        with self.assertRaisesRegex(lifecycle.Blocked, 'explicit migration'):
            obj.app_init()
        self.assertEqual(json.loads((obj.state / 'backend.json').read_text()), {'storage_account_name': 'old'})

    def test_existing_local_state_is_preserved_and_private(self):
        obj = self.prepare_namespace()
        state = obj.state / 'application.tfstate'
        value = {'version': 4, 'resources': [], 'serial': 17}
        lifecycle.save_json(state, value)
        state.chmod(0o644)
        obj.app_init()
        self.assertEqual(json.loads(state.read_text()), value)
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_symlink_artifact_blocks_before_init(self):
        obj = self.prepare_namespace()
        (obj.state / 'application.tfstate').symlink_to(obj.app / 'other')
        with self.assertRaisesRegex(lifecycle.Blocked, 'symlinks'):
            obj.app_init()
        obj.tf.assert_not_called()

    def test_unexpected_state_is_not_ignored(self):
        obj = self.prepare_namespace()
        lifecycle.save_json(obj.state / 'unknown.tfstate', {'backend': {'type': 'azurerm'}})
        with self.assertRaisesRegex(lifecycle.Blocked, 'unexpected persistent state'):
            obj.app_init()
        obj.tf.assert_not_called()

    def test_nondefault_workspace_and_unknown_state_fail_closed(self):
        obj = self.prepare_namespace()
        data = obj.state / 'application-data'
        data.mkdir()
        (data / 'environment').write_text('production')
        with self.assertRaisesRegex(lifecycle.Blocked, 'workspace'):
            obj.app_init()
        (data / 'environment').write_text('default')
        lifecycle.save_json(obj.state / 'application.tfstate', {})
        with self.assertRaisesRegex(lifecycle.Blocked, 'unknown application state'):
            obj.app_init()
        obj.tf.assert_not_called()


    def test_foreign_artifact_owner_blocks(self):
        obj = self.prepare_namespace()
        lifecycle.save_json(obj.state / 'application.tfstate', {'version': 4, 'resources': []})
        with patch.object(lifecycle.os, 'getuid', return_value=-1):
            with self.assertRaisesRegex(lifecycle.Blocked, 'ownership'):
                obj.local_backend_check()


class NamespaceTerraform(unittest.TestCase):
    setUp = lambda self: Orchestration.setUp(self)

    def foundation(self, existing=False, code=0):
        obj = self.instance
        obj.az = Mock(side_effect=AssertionError('foundation must not use Azure'))
        obj.xc = Mock(return_value={'metadata': {'name': lifecycle.FIXED['namespace']},
                                   'system_metadata': {'uid': 'confirmed-live-uid'}})
        identity = {'name': lifecycle.FIXED['namespace'], 'id': lifecycle.FIXED['namespace']}
        lifecycle.save_json(obj.state / 'namespace-receipt.json',
                            {'path': '/api/web/namespaces/webapp-api-protection', 'uid': 'confirmed-live-uid'})
        self.state_value = {'version': 4, 'resources': [{'mode': 'managed', 'type': 'xcsh_namespace', 'name': 'this',
                            'instances': [{'attributes': identity}]}]}
        self.show = {'values': {'root_module': {'resources': [{'mode': 'managed', 'type': 'xcsh_namespace',
                     'address': 'xcsh_namespace.this', 'values': identity}]}}}
        self.plan = {'resource_changes': [{'mode': 'managed', 'type': 'xcsh_namespace', 'address': 'xcsh_namespace.this',
                     'change': {'actions': ['no-op'], 'before': identity.copy(), 'after': identity.copy()}}],
                     'output_changes': {'namespace_name': {'actions': ['no-op'], 'after': identity['name']},
                                        'namespace_id': {'actions': ['no-op'], 'after': identity['id']}}}
        if existing:
            lifecycle.save_json(obj.state / 'namespace.tfstate', self.state_value)
        def tf(directory, *argv, **kwargs):
            self.assertEqual(directory, obj.namespace_root)
            if argv[0] == 'import':
                lifecycle.save_json(obj.state / 'namespace.tfstate', self.state_value)
            if argv[0] == 'show':
                return json.dumps(self.plan if len(argv) == 3 else self.show), 0
            if argv[0] == 'plan':
                (obj.state / 'namespace.plan').write_text('saved-plan')
                return '', code
            return '', 0
        obj.tf = Mock(side_effect=tf)
        return obj

    def verbs(self, obj):
        return [c.args[1] for c in obj.tf.call_args_list]

    def test_fresh_import_uses_confirmed_identity_and_saved_plan(self):
        obj = self.foundation(code=2)
        obj.namespace_tf_prepare(create=True)
        self.assertEqual(self.verbs(obj).count('import'), 1)
        obj.tf.assert_any_call(obj.namespace_root, 'import', '-input=false', 'xcsh_namespace.this', 'webapp-api-protection')
        obj.tf.assert_any_call(obj.namespace_root, 'init', '-input=false', '-backend-config=' + str(obj.state / 'namespace-backend.json'))
        obj.tf.assert_any_call(obj.namespace_root, 'apply', '-input=false', str(obj.state / 'namespace.plan'))
        self.assertEqual(json.loads((obj.state / 'namespace-receipt.json').read_text())['uid'], 'confirmed-live-uid')
        self.assertEqual((obj.state / 'namespace.plan').stat().st_mode & 0o777, 0o600)
        obj.az.assert_not_called()

    def test_existing_state_never_reimported(self):
        obj = self.foundation(existing=True)
        obj.namespace_tf_prepare(create=True)
        self.assertNotIn('import', self.verbs(obj))

    def test_preservation_is_readonly_and_missing_state_blocks(self):
        obj = self.foundation(existing=True)
        obj.namespace_tf_prepare()
        self.assertNotIn('import', self.verbs(obj))
        self.assertNotIn('apply', self.verbs(obj))
        (obj.state / 'namespace.tfstate').unlink()
        obj.tf.reset_mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'state missing'):
            obj.namespace_tf_prepare()
        obj.tf.assert_not_called()

    def test_import_without_prior_confirmed_uid_is_refused(self):
        obj = self.foundation()
        (obj.state / 'namespace-receipt.json').unlink()
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID evidence missing'):
            obj.namespace_tf_prepare(create=True)
        obj.tf.assert_not_called()

    def test_existing_state_without_uid_evidence_is_refused(self):
        obj = self.foundation(existing=True)
        (obj.state / 'namespace-receipt.json').unlink()
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID evidence missing'):
            obj.namespace_prepare()
        obj.tf.assert_not_called()

    def test_verify_cannot_enable_namespace_import_or_apply(self):
        obj = self.foundation()
        obj.operation = 'verify'
        with self.assertRaisesRegex(lifecycle.Blocked, 'only during deployment'):
            obj.namespace_tf_prepare(create=True)
        obj.tf.assert_not_called()


    def test_uid_mismatch_blocks_before_import(self):
        obj = self.foundation()
        lifecycle.save_json(obj.state / 'namespace-receipt.json', {'path': '/api/web/namespaces/webapp-api-protection', 'uid': 'different'})
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID changed'):
            obj.namespace_tf_prepare(create=True)
        obj.tf.assert_not_called()

    def test_uid_change_during_import_blocks_apply(self):
        obj = self.foundation()
        good = obj.xc.return_value
        bad = {'metadata': good['metadata'], 'system_metadata': {'uid': 'changed'}}
        obj.xc.side_effect = [good, good, bad]
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID changed'):
            obj.namespace_tf_prepare(create=True)
        self.assertNotIn('apply', self.verbs(obj))

    def test_plan_mutations_unknown_and_replacements_block(self):
        for actions in (['create'], ['update'], ['delete'], ['delete', 'create'], ['create', 'delete']):
            with self.subTest(actions=actions):
                obj = self.foundation(existing=True)
                self.plan['resource_changes'][0]['change']['actions'] = actions
                with self.assertRaisesRegex(lifecycle.Blocked, 'mutation refused'):
                    obj.namespace_tf_prepare(create=True)
                self.assertNotIn('apply', self.verbs(obj))
        obj = self.foundation(existing=True)
        self.plan['resource_changes'].append({'mode': 'data', 'type': 'unknown'})
        with self.assertRaisesRegex(lifecycle.Blocked, 'mutation refused'):
            obj.namespace_tf_prepare(create=True)

    def test_unknown_state_and_wrong_imported_id_block(self):
        obj = self.foundation(existing=True)
        self.state_value['resources'][0]['type'] = 'xcsh_origin_pool'
        lifecycle.save_json(obj.state / 'namespace.tfstate', self.state_value)
        with self.assertRaisesRegex(lifecycle.Blocked, 'unknown namespace state'):
            obj.namespace_tf_prepare(create=True)
        obj.tf.assert_not_called()
        (obj.state / 'namespace.tfstate').unlink()
        obj = self.foundation()
        self.show['values']['root_module']['resources'][0]['values']['id'] = 'system/other'
        with self.assertRaisesRegex(lifecycle.Blocked, 'state identity mismatch'):
            obj.namespace_tf_prepare(create=True)
        self.assertNotIn('apply', self.verbs(obj))

    def test_destroy_drift_blocks_before_application_actions(self):
        obj = self.foundation(existing=True, code=2)
        obj.operation = 'destroy'
        obj.app_init = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'zero-change'):
            obj.destroy()
        obj.app_init.assert_not_called()
        self.assertNotIn('apply', self.verbs(obj))

    def test_unknown_plan_identity_and_outputs_block(self):
        for mutation in ('id', 'unknown', 'output'):
            with self.subTest(mutation=mutation):
                obj = self.foundation(existing=True)
                if mutation == 'id':
                    self.plan['resource_changes'][0]['change']['after']['id'] = 'system/other'
                elif mutation == 'unknown':
                    self.plan['resource_changes'][0]['change']['after_unknown'] = {'id': True}
                else:
                    self.plan['output_changes']['namespace_id']['after'] = 'fabricated-uid'
                with self.assertRaises(lifecycle.Blocked):
                    obj.namespace_tf_prepare(create=True)
                self.assertNotIn('apply', self.verbs(obj))

    def test_namespace_provider_id_is_bare_name_not_preservation_receipt(self):
        obj = self.foundation(existing=True)
        obj.namespace_tf_prepare()
        self.assertEqual(obj.persistent['namespace'], 'system/webapp-api-protection')
        self.state_value['resources'][0]['instances'][0]['attributes']['id'] = obj.persistent['namespace']
        lifecycle.save_json(obj.state / 'namespace.tfstate', self.state_value)
        obj.tf.reset_mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'unknown namespace state identity'):
            obj.namespace_tf_prepare()
        obj.tf.assert_not_called()


    def test_runtime_roots_are_isolated_and_auth_is_preserved(self):
        obj = self.instance
        obj.env['XCSH_API_TOKEN'] = 'test-only-token'
        obj.run = Mock(return_value=('', 0))
        for root, label in ((obj.app, 'application'), (obj.namespace_root, 'namespace')):
            with patch.object(lifecycle.os, 'umask', wraps=lifecycle.os.umask) as umask:
                obj.tf(root, 'init')
                umask.assert_called_once_with(0o077)
            env = obj.run.call_args.kwargs['env']
            self.assertEqual(env['TF_DATA_DIR'], str(obj.state / (label + '-data')))
            self.assertEqual(env['TF_WORKSPACE'], 'default')
            self.assertEqual(env['XCSH_API_TOKEN'], 'test-only-token')
        with self.assertRaisesRegex(lifecycle.Blocked, 'unknown Terraform root'):
            obj.tf(obj.app / 'other', 'init')

    def test_namespace_destroy_commands_are_always_refused(self):
        obj = self.instance
        obj.run = Mock()
        for args in (('destroy',), ('plan', '-destroy'), ('apply', '-destroy')):
            with self.subTest(args=args), self.assertRaisesRegex(lifecycle.Blocked, 'destroy prohibited'):
                obj.tf(obj.namespace_root, *args)
        obj.run.assert_not_called()


    def test_namespace_backend_cannot_point_at_application_state(self):
        obj = self.instance
        data = obj.state / 'namespace-data'
        data.mkdir()
        lifecycle.save_json(data / 'terraform.tfstate',
                            {'backend': {'type': 'local', 'config': obj.backend}})
        obj.run = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'different backend'):
            obj.tf(obj.namespace_root, 'init')
        obj.run.assert_not_called()

    def test_namespace_state_backup_and_metadata_are_private(self):
        obj = self.foundation(existing=True)
        backup = obj.state / 'namespace.tfstate.backup'
        lifecycle.save_json(backup, self.state_value)
        backup.chmod(0o644)
        data = obj.state / 'namespace-data'
        data.mkdir()
        metadata = data / 'terraform.tfstate'
        lifecycle.save_json(metadata, {'backend': {'type': 'local', 'config': obj.namespace_backend}})
        metadata.chmod(0o644)
        data.chmod(0o755)
        obj.local_backend_check()
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)
        self.assertEqual(data.stat().st_mode & 0o777, 0o700)

    def test_actual_namespace_root_matches_lifecycle_contract(self):
        root = Path(__file__).resolve().parents[1] / 'terraform'
        source = (root / 'namespace/main.tf').read_text()
        outputs = (root / 'namespace/outputs.tf').read_text()
        for required in ('backend "local" {}', 'provider "xcsh" {}', 'f5-sales-demo/xcsh',
                         '"= 12.0.2"', 'resource "xcsh_namespace" "this"', 'prevent_destroy = true'):
            self.assertIn(required, source)
        self.assertIn('var.namespace == "webapp-api-protection"', source)
        self.assertIn('value       = xcsh_namespace.this.id', outputs)
        self.assertNotIn('namespace_uid', outputs)
        self.assertFalse(any('resource "xcsh_namespace"' in path.read_text() for path in root.glob('*.tf')))


    def test_unrelated_file_permissions_are_not_clobbered(self):
        obj = self.instance
        unrelated = obj.state / 'operator-notes.txt'
        unrelated.write_text('owned but unrelated')
        unrelated.chmod(0o644)
        obj.local_backend_check()
        self.assertEqual(unrelated.stat().st_mode & 0o777, 0o644)



class LocalTerraformRuntime(unittest.TestCase):
    setUp = lambda self: Orchestration.setUp(self)

    @unittest.skipUnless(lifecycle.shutil.which('terraform'), 'Terraform unavailable')
    def test_external_state_permissions_backup_and_native_file_lock(self):
        obj = self.instance
        obj.deadline = time.monotonic() + 60
        inherited_umask, _ = obj.run([sys.executable, '-c', 'import os; print(os.umask(0o077))'])
        self.assertEqual(int(inherited_umask), 0o077)
        hcl = obj.app / 'main.tf'
        hcl.write_text('terraform {\n  backend "local" {}\n}\nresource "terraform_data" "proof" {\n  input = "first"\n}\n')
        obj.tf(obj.app, 'fmt')
        obj.app_init()
        metadata = json.loads((obj.state / 'application-data/terraform.tfstate').read_text())
        self.assertEqual(metadata['backend']['type'], 'local')
        self.assertEqual(metadata['backend']['config']['path'], obj.backend['path'])
        obj.tf(obj.app, 'apply', '-input=false', '-auto-approve')
        state = obj.state / 'application.tfstate'
        self.assertTrue(state.is_file())
        self.assertFalse(list(obj.app.rglob('*.tfstate')))
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(obj.state.stat().st_mode & 0o777, 0o700)
        # Terraform uses POSIX record locking, distinct from the outer lifecycle flock.
        holder = subprocess.Popen([sys.executable, '-c',
            'import fcntl,sys; f=open(sys.argv[1], "r+"); fcntl.lockf(f, fcntl.LOCK_EX); print("locked", flush=True); sys.stdin.read(1)',
            str(state)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), 'locked')
            with self.assertRaisesRegex(lifecycle.Blocked, 'state-lock'):
                obj.tf(obj.app, 'plan', '-input=false', '-lock-timeout=0s')
        finally:
            holder.communicate(input='x', timeout=5)
        obj.tf(obj.app, 'plan', '-input=false')
        hcl.write_text(hcl.read_text().replace('"first"', '"second"'))
        obj.tf(obj.app, 'apply', '-input=false', '-auto-approve')
        backup = obj.state / 'application.tfstate.backup'
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        serial = json.loads(state.read_text())['serial']
        obj.app_init()
        self.assertEqual(json.loads(state.read_text())['serial'], serial)
        obj.tf(obj.app, 'apply', '-destroy', '-input=false', '-auto-approve')
        self.assertEqual(json.loads(state.read_text())['resources'], [])
        self.assertTrue(backup.is_file())
        self.assertFalse(list(obj.app.rglob('*.tfstate')))

    def test_uninitialized_runtime_cannot_default_to_checkout_state(self):
        obj = self.instance
        obj.run = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'not initialized'):
            obj.tf(obj.app, 'apply', '-auto-approve')
        obj.run.assert_not_called()

    def test_state_lock_and_migration_overrides_rejected(self):
        obj = self.instance
        obj.run = Mock()
        for option in ('-lock=false', '-state=/tmp/state', '-migrate-state', '-reconfigure', '-force-copy', '-backend=false'):
            with self.subTest(option=option), self.assertRaisesRegex(lifecycle.Blocked, 'override'):
                obj.tf(obj.app, 'init', option)
        obj.run.assert_not_called()



class Orchestration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / 'checkout'
        (self.root / 'terraform').mkdir(parents=True)
        (self.root / 'terraform/showcase.tfvars.json').write_text('{}')
        config = base / 'operator.json'
        lifecycle.save_json(config, dict(TEST_APPROVAL, expected_azure_user='operator@example.test'))
        args = SimpleNamespace(operation='deploy', config=config, state_dir=base / 'state', timeout_seconds=30)
        self.instance = lifecycle.Lifecycle(args, self.root)
        (self.instance.namespace_root).mkdir()

    def fake_deploy(self, fail_ready=False):
        obj = self.instance
        calls = []
        obj.namespace_tf_prepare = lambda create=False: calls.append('backend')
        obj.app_init = lambda: calls.append('init')
        obj.run = lambda *a, **kw: ('/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/v1', 0)
        obj.plan = lambda name, *a: calls.append(name) or Path(name)
        obj.tf = lambda *a, **kw: calls.append('apply') or ('', 0)
        obj.get_outputs = lambda: calls.append('outputs')
        obj.inventory = lambda: calls.append('inventory')
        def verify(phase):
            calls.append(phase)
            if phase == 'readiness' and fail_ready:
                raise lifecycle.Blocked('not ready')
        obj.verify_phase = verify
        obj.traffic = lambda action: calls.append('traffic-' + action)
        return calls

    def test_deploy_order_and_noop_apply(self):
        calls = self.fake_deploy()
        self.instance.deploy()
        self.assertEqual(calls, ['backend', 'init', 'application', 'apply', 'outputs',
                                 'inventory', 'readiness', 'traffic-start', 'acceptance',
                                 'post-acceptance-drift', 'apply'])
        generated = json.loads(self.instance.vars.read_text())
        self.assertEqual(generated['api_definition_swagger_specs'], ['/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/v1'])

    def test_deploy_refreshes_stale_private_mud_profile_from_canonical_profile(self):
        canonical = Path(__file__).resolve().parents[1] / 'terraform/showcase.tfvars.json'
        (self.root / 'terraform/showcase.tfvars.json').write_text(canonical.read_text())
        lifecycle.save_json(self.instance.vars, {'mud_enabled': True, 'mud_bad_traffic': False})
        self.fake_deploy()
        self.instance.deploy()
        generated = json.loads(self.instance.vars.read_text())
        self.assertIs(generated['mud_enabled'], True)
        self.assertIs(generated['mud_bad_traffic'], True)

    def test_readiness_failure_never_starts_traffic(self):
        calls = self.fake_deploy(True)
        with self.assertRaises(lifecycle.Blocked):
            self.instance.deploy()
        self.assertNotIn('traffic-start', calls)
        self.assertNotIn('acceptance', calls)

    def test_unpinned_upload_blocks_before_app_plan(self):
        calls = self.fake_deploy()
        self.instance.run = lambda *a, **kw: ('/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/latest', 0)
        with self.assertRaises(lifecycle.Blocked):
            self.instance.deploy()
        self.assertNotIn('application', calls)

    def test_missing_external_namespace_blocks(self):
        self.instance.xc = Mock(return_value=None)
        with self.assertRaisesRegex(lifecycle.Blocked, 'namespace missing'):
            self.instance.namespace_prepare()

    def test_existing_group_never_adopted(self):
        self.instance.az = Mock(return_value=True)
        plan = {'resource_changes': [{'type': 'azurerm_resource_group', 'change': {'actions': ['create'], 'after': {'name': 'existing'}}}]}
        with self.assertRaises(lifecycle.Blocked):
            self.instance.guard_conflicts(plan)

    def test_unowned_child_blocks_destroy(self):
        rid = '/subscriptions/s/resourceGroups/g'
        self.instance.az = Mock(return_value=[{'id': rid + '/providers/Microsoft.Compute/disks/unowned'}])
        resources = [{'type': 'azurerm_resource_group', 'values': {'id': rid, 'name': 'g'}}]
        with self.assertRaises(lifecycle.Blocked):
            self.instance.guard_group_children(resources)

    def test_process_timeout_is_nonzero(self):
        self.instance.deadline = time.monotonic() + .05
        with self.assertRaises(subprocess.TimeoutExpired):
            self.instance.run([sys.executable, '-c', 'import time; time.sleep(10)'])

    def test_shell_payload_remains_literal_argument(self):
        payload = '$(touch /tmp/lifecycle-no-shell); echo unsafe'
        stdout, code = self.instance.run([sys.executable, '-c', 'import sys; print(sys.argv[1])', payload])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), payload)

    def test_rebuild_holds_one_outer_lock(self):
        obj = self.instance
        obj.operation = 'rebuild'
        calls = []
        obj.preflight = lambda deploying: (calls.append('preflight'), obj.capacity_permissions())
        obj.destroy = lambda: calls.append('destroy')
        obj.capacity_permissions = lambda: calls.append('quota')
        obj.deploy = lambda: calls.append('deploy')
        obj.execute()
        self.assertEqual(calls, ['preflight', 'quota', 'destroy', 'deploy'])
        self.assertEqual(obj.receipt['status'], 'verified')

    def test_cleanup_never_masks_primary_failure(self):
        obj = self.instance
        obj.preflight = Mock()
        obj.deploy = Mock(side_effect=lifecycle.Blocked('primary failure'))
        obj.traffic = Mock(side_effect=lifecycle.Blocked('cleanup failure'))
        with self.assertRaisesRegex(lifecycle.Blocked, 'primary failure'):
            obj.execute()
        receipt = json.loads((obj.state / 'operation-receipt.json').read_text())
        self.assertEqual(receipt['status'], 'blocked')
        self.assertEqual(receipt['error'], 'primary failure')

    def test_missing_tool_blocks_preflight(self):
        with patch.object(lifecycle.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(lifecycle.Blocked, 'missing prerequisite'):
                self.instance.preflight(True)

    def test_destroy_requires_exact_captured_id(self):
        plan = {'resource_changes': [{'address': 'vm.main', 'type': 'azurerm_linux_virtual_machine',
                                      'change': {'actions': ['delete'], 'before': {'id': 'other'}}}]}
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan(plan, 'destroy', {'vm.main': 'owned'})

    def test_persistent_id_blocks_even_allowed_type(self):
        plan = {'resource_changes': [{'address': 'rg.main', 'type': 'azurerm_resource_group',
                                      'change': {'actions': ['delete'], 'before': {'id': 'persistent'}}}]}
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.guard_plan(plan, 'destroy', {'rg.main': 'persistent'}, ['persistent'])

    def test_symlink_directory_rejected(self):
        link = Path(self.temp.name) / 'link'
        link.symlink_to(self.instance.state, target_is_directory=True)
        with self.assertRaises(lifecycle.Blocked):
            lifecycle.secure_directory(link, self.root)

    def test_reentrant_lock_rejected(self):
        with (self.instance.state / 'lifecycle.lock').open('a') as stream:
            lifecycle.fcntl.flock(stream, lifecycle.fcntl.LOCK_EX)
            with self.assertRaisesRegex(lifecycle.Blocked, 'another lifecycle'):
                self.instance.execute()



class RuntimeContract(unittest.TestCase):
    setUp = Orchestration.setUp

    def test_acceptance_verifier_exit_code_is_not_success(self):
        obj = self.instance
        scripts = self.root / 'scripts'
        scripts.mkdir()
        (scripts / 'demo-verify.sh').write_text('exit 2\n')
        obj.preflight = Mock()
        obj.enroll_guests = Mock()
        obj.deploy = lambda: obj.verify_phase('acceptance')
        obj.traffic = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'bash exit 2'):
            obj.execute()
        self.assertEqual(obj.receipt['commands'][-1]['exit_code'], 2)
        self.assertNotIn('live-acceptance', [p['name'] for p in obj.receipt['phases']])
        obj.traffic.assert_called_once_with('stop', cleanup=True)




    def test_registry_configuration_is_not_inherited(self):
        self.assertEqual(self.instance.env['TF_CLI_CONFIG_FILE'], '/dev/null')
        self.assertNotIn('TF_PLUGIN_CACHE_DIR', self.instance.env)

    def test_cached_backend_migration_failure_is_not_reconfigured(self):
        obj = self.instance
        obj.tf = Mock(side_effect=lifecycle.Blocked('required subprocess failed: terraform exit 1 (state-lock)'))
        with self.assertRaises(lifecycle.Blocked):
            obj.app_init()
        self.assertEqual(obj.tf.call_count, 1)
        self.assertFalse(obj.app_ready)
        self.assertNotIn('-reconfigure', obj.tf.call_args.args)
        self.assertNotIn('-migrate-state', obj.tf.call_args.args)

    def test_runtime_fmt_excludes_fixture_and_test_roots(self):
        obj = self.instance
        (obj.app / 'main.tf').write_text('terraform {}\n')
        for folder in ('tests', 'fixtures', 'modules/http-lb'):
            target = obj.app / folder
            target.mkdir(parents=True)
            (target / 'main.tf').write_text('terraform {}\n')
        obj.tf = Mock(return_value=('', 0))
        obj.app_init()
        fmt = [c.args for c in obj.tf.call_args_list if 'fmt' in c.args]
        self.assertEqual(len(fmt), 2)
        self.assertTrue(all('-recursive' not in c for c in fmt))
        self.assertEqual({c[0] for c in fmt}, {obj.app})
        self.assertEqual({str(c[-1]) for c in fmt}, {str(obj.app / 'main.tf'), str(obj.app / 'modules/http-lb/main.tf')})

    def test_profile_uses_actual_user_identification_mode(self):
        root = Path(__file__).resolve().parents[1]
        profile = json.loads((root / 'terraform/showcase.tfvars.json').read_text())
        self.assertEqual(profile['mud_user_id'], 'user_identification')
        self.assertEqual(profile['mud_user_id_rule'], 'http_header_name')
        self.assertEqual(profile['rate_limit_choice'], 'api_rate_limit')

    def test_nonzero_acceptance_is_redacted_and_stops_traffic(self):
        obj = self.instance
        obj.preflight = Mock()
        obj.deploy = lambda: obj.run([sys.executable, '-c', 'import sys; print("secret-token", file=sys.stderr); sys.exit(7)'])
        obj.traffic = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'exit 7') as caught:
            obj.execute()
        obj.traffic.assert_called_once_with('stop', cleanup=True)
        receipt = json.loads((obj.state / 'operation-receipt.json').read_text())
        self.assertEqual(receipt['status'], 'blocked')
        self.assertEqual(receipt['commands'][-1]['exit_code'], 7)
        self.assertNotIn('secret-token', str(caught.exception) + json.dumps(receipt))

    def test_interrupt_retains_primary_failure_and_stops_traffic(self):
        obj = self.instance
        obj.preflight = Mock()
        obj.deploy = Mock(side_effect=KeyboardInterrupt)
        obj.traffic = Mock()
        with self.assertRaises(KeyboardInterrupt):
            obj.execute()
        obj.traffic.assert_called_once_with('stop', cleanup=True)
        self.assertEqual(obj.receipt['error'], 'KeyboardInterrupt')

    def test_xc_conflict_or_unknown_identity_blocks(self):
        obj = self.instance
        obj.xc = Mock(return_value={'metadata': {'name': 'existing'}})
        plan = {'resource_changes': [{'type': 'xcsh_origin_pool', 'change': {'actions': ['create'], 'after': {'name': 'existing', 'namespace': lifecycle.FIXED['namespace']}}}]}
        with self.assertRaisesRegex(lifecycle.Blocked, 'conflict'):
            obj.guard_conflicts(plan)
        obj.xc.assert_called_once()
        plan['resource_changes'][0]['change']['after']['name'] = None
        obj.xc.reset_mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'unknown XC'):
            obj.guard_conflicts(plan)
        obj.xc.assert_not_called()

    def test_arm_manifest_captures_external_storage_versions(self):
        obj = self.instance
        group = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/demo'
        storage = group + '/providers/Microsoft.Storage/storageAccounts/state'
        container = storage + '/blobServices/default/containers/tfstate'
        catalogs = {
            'Microsoft.Resources': [{'resourceType': 'resourceGroups', 'apiVersions': ['2024-03-01']}],
            'Microsoft.Storage': [{'resourceType': 'storageAccounts', 'apiVersions': ['2024-01-01']}, {'resourceType': 'storageAccounts/blobServices/containers', 'apiVersions': ['2023-05-01', '2025-01-01-preview']}],
        }
        obj.az = Mock(side_effect=lambda *a: {'resourceTypes': catalogs[a[-1]]})
        self.assertEqual(obj.azure_api_versions([group, storage, container]),
                         {group: '2024-03-01', storage: '2024-01-01', container: '2023-05-01'})
        self.assertEqual(obj.az.call_count, 2)
        with self.assertRaisesRegex(lifecycle.Blocked, 'scope'):
            obj.azure_api_versions(['/subscriptions/other/resourceGroups/demo'])
        obj.az = Mock(return_value={'resourceTypes': []})
        with self.assertRaisesRegex(lifecycle.Blocked, 'no advertised stable'):
            obj.azure_api_versions([storage])

    def child_version_fixture(self, versions=None):
        obj = self.instance
        base = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/originlab/providers/Microsoft.Network/virtualNetworks/owned/subnets/'
        versions = versions or ['2026-05-01', '2025-01-01', '2024-01-01', '2023-01-01']
        def az(*args):
            if args[0] == 'provider':
                return {'resourceTypes': [{'resourceType': 'virtualNetworks', 'apiVersions': versions}]}
            rid = args[-1].split('?')[0].removeprefix('https://management.azure.com')
            return {'id': rid, 'properties': {'provisioningState': 'Succeeded'}}
        obj.az = Mock(side_effect=az)
        return obj, base, az

    def test_missing_child_advertisement_confirms_each_exact_owned_child(self):
        obj, base, _ = self.child_version_fixture()
        ids = [base + 'origin', base + 'generator']
        self.assertEqual(obj.azure_api_versions(ids), {rid: '2026-05-01' for rid in ids})
        self.assertEqual(obj.az.call_count, 3)
        self.assertEqual([c.args[-1] for c in obj.az.call_args_list[1:]],
                         ['https://management.azure.com' + rid + '?api-version=2026-05-01' for rid in ids])

    def test_child_candidates_skip_only_explicit_unsupported_versions(self):
        obj, base, previous = self.child_version_fixture()
        def az(*args):
            if args[0] == 'rest' and args[-1].endswith('2026-05-01'):
                raise lifecycle.Blocked('required subprocess failed: az exit 1 (arm-api-version-unsupported)')
            return previous(*args)
        obj.az.side_effect = az
        self.assertEqual(obj.azure_api_versions([base + 'origin', base + 'generator']),
                         {base + 'origin': '2025-01-01', base + 'generator': '2025-01-01'})
        self.assertEqual(obj.az.call_count, 4)

    def test_child_candidates_bound_all_unsupported_reads(self):
        obj, base, previous = self.child_version_fixture()
        def az(*args):
            if args[0] == 'rest':
                raise lifecycle.Blocked('required subprocess failed: az exit 1 (arm-api-version-unsupported)')
            return previous(*args)
        obj.az.side_effect = az
        with self.assertRaisesRegex(lifecycle.Blocked, 'no confirmed stable'):
            obj.azure_api_versions([base + 'origin'])
        self.assertEqual(obj.az.call_count, 4)

    def test_child_candidates_never_fallback_on_absence_denial_or_timeout(self):
        for error in (lifecycle.Blocked('HTTP-403-permission'), lifecycle.Blocked('HTTP-401-authentication'),
                      lifecycle.Blocked('ResourceNotFound 404'), lifecycle.Blocked('timeout'),
                      subprocess.TimeoutExpired('az', 1)):
            with self.subTest(error=str(error)):
                obj, base, previous = self.child_version_fixture()
                def az(*args):
                    if args[0] == 'rest':
                        raise error
                    return previous(*args)
                obj.az.side_effect = az
                with self.assertRaises(type(error)):
                    obj.azure_api_versions([base + 'origin'])
                self.assertEqual(obj.az.call_count, 2)

    def test_child_read_requires_exact_identity_and_success(self):
        for live in ({}, {'id': 'wrong', 'properties': {'provisioningState': 'Succeeded'}},
                     {'properties': {'provisioningState': 'Failed'}}, {'properties': {}},
                     {'properties': {'provisioningState': 'Updating'}}, {'properties': None},
                     {'properties': []}):
            with self.subTest(live=live):
                obj, base, previous = self.child_version_fixture()
                def az(*args):
                    if args[0] == 'provider':
                        return previous(*args)
                    return dict({'id': base + 'origin'}, **live)
                obj.az.side_effect = az
                with self.assertRaises(lifecycle.Blocked):
                    obj.azure_api_versions([base + 'origin'])
                self.assertEqual(obj.az.call_count, 2)

    def test_child_missing_stable_ancestor_blocks_without_live_read(self):
        obj, base, _ = self.child_version_fixture(['2026-05-01-preview'])
        with self.assertRaisesRegex(lifecycle.Blocked, 'no advertised stable'):
            obj.azure_api_versions([base + 'origin'])
        self.assertEqual(obj.az.call_count, 1)

    def test_child_uses_nearest_advertised_ancestor_only(self):
        obj, base, _ = self.child_version_fixture()
        catalogs = [{'resourceType': 'virtualNetworks', 'apiVersions': ['2026-05-01']},
                    {'resourceType': 'virtualNetworks/subnets', 'apiVersions': ['2024-01-01']}]
        rid = base + 'origin/children/child'
        obj.az.side_effect = lambda *a: {'resourceTypes': catalogs} if a[0] == 'provider' else {
            'id': rid, 'properties': {'provisioningState': 'Succeeded'}}
        self.assertEqual(obj.azure_api_versions([rid]), {rid: '2024-01-01'})
        self.assertTrue(obj.az.call_args.args[-1].endswith('api-version=2024-01-01'))

    def test_subprocess_version_error_classification_preserves_denial_priority(self):
        obj = self.instance
        for stderr, expected in [('ERROR: (InvalidApiVersionParameter)', 'arm-api-version-unsupported'),
                                 ('ERROR: (UnsupportedApiVersion)', 'arm-api-version-unsupported'),
                                 ('403 InvalidApiVersionParameter', 'HTTP-403-permission'),
                                 ('401 UnsupportedApiVersion', 'authentication'),
                                 ('ResourceNotFound 404', 'upstream-output-withheld'),
                                 ('request timeout', 'timeout')]:
            with self.subTest(stderr=stderr):
                process = Mock(returncode=1)
                process.communicate.return_value = ('', stderr)
                with patch.object(lifecycle.subprocess, 'Popen', return_value=process):
                    with self.assertRaisesRegex(lifecycle.Blocked, expected):
                        obj.run(['az', 'rest'])
                self.assertEqual(obj.receipt['commands'][-1]['diagnostic'], expected)

    def test_subprocess_diagnostics_are_bounded_and_redacted(self):
        cases = [
            ('terraform', 'HTTP 400: Oneof fields should be exclusive: blocking_page, '
             'use_default_blocking_page; body=string:///secret-token', 'HTTP-400-configuration'),
            ('terraform', 'Error: Oneof fields should be exclusive: blocking_page, '
             'use_default_blocking_page', 'upstream-output-withheld'),
            ('terraform', 'Error acquiring the state lock\nError message: resource temporarily unavailable',
             'state-lock'),
            ('terraform', 'Error releasing the state lock', 'state-lock'),
            ('terraform', 'request blocked by policy; lock_timeout=30', 'upstream-output-withheld'),
            ('az', 'state lock field rejected', 'upstream-output-withheld'),
            ('az', 'https://example.invalid/401?code=403&quota=unlimited&timeout=30',
             'upstream-output-withheld'),
            ('az', 'https://example.invalid/401/path/403?status=401', 'upstream-output-withheld'),
            ('az', 'account 401234; resource 403999; block quota_limit timeout_seconds',
             'upstream-output-withheld'),
            ('az', 'AuthorizationFailed: secret-token', 'permission'),
            ('az', 'AuthorizationPermissionMismatch: secret-token', 'blob-data-permission'),
            ('az', 'quota exceeded: secret-token', 'quota'),
            ('az', 'request timeout: secret-token', 'timeout'),
        ]
        for program, stderr, expected in cases:
            with self.subTest(program=program, stderr=stderr):
                process = Mock(returncode=1)
                process.communicate.return_value = ('secret-stdout', stderr)
                with patch.object(lifecycle.subprocess, 'Popen', return_value=process):
                    with self.assertRaisesRegex(lifecycle.Blocked, expected) as caught:
                        self.instance.run([program, 'apply'])
                receipt = json.loads((self.instance.state / 'operation-receipt.json').read_text())
                self.assertEqual(receipt['commands'][-1]['diagnostic'], expected)
                self.assertEqual(receipt['commands'][-1]['exit_code'], 1)
                persisted = str(caught.exception) + json.dumps(receipt)
                for secret in ('secret-token', 'secret-stdout', 'string:///'):
                    self.assertNotIn(secret, persisted)
                self.assertNotIn(stderr, persisted)


    def test_premature_inventory_cannot_clobber_receipt(self):
        obj = self.instance
        path = obj.state / 'run-manifest.json'
        lifecycle.save_json(path, {'persistent_resource_ids': {'namespace': 'system/webapp-api-protection'}})
        before = path.read_bytes()
        obj.tf, obj.xc = Mock(), Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'foundation not initialized'):
            obj.inventory()
        self.assertEqual(path.read_bytes(), before)
        obj.tf.assert_not_called()
        obj.xc.assert_not_called()

    def recovery_setup(self):
        obj = self.instance
        ns = lifecycle.FIXED['namespace']
        identity = {'path': '/api/web/namespaces/' + ns, 'uid': 'uid-' + ns}
        lifecycle.save_json(obj.state / 'persistent.json', {'namespace': 'system/' + ns})
        lifecycle.save_json(obj.state / 'namespace-receipt.json', identity)
        lifecycle.save_json(obj.state / 'namespace.tfstate', {'resources': [
            {'mode': 'managed', 'type': 'xcsh_namespace', 'name': 'this', 'instances': [
                {'attributes': {'name': ns, 'id': ns}}]}]})
        obj.persistent = {'namespace': 'system/' + ns}
        obj.namespace_uid = identity['uid']
        rid = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/application'
        resources = [{'mode': 'managed', 'type': 'azurerm_resource_group', 'address': 'rg.main',
                      'values': {'id': rid, 'name': 'application'}}]
        obj.tf = Mock(return_value=(json.dumps({'values': {'root_module': {'resources': resources}}}), 0))
        obj.xc = Mock(return_value={'metadata': {'name': ns}, 'system_metadata': {'uid': identity['uid']}})
        obj.azure_api_versions = Mock(return_value={rid: '2024-01-01'})
        obj.az = Mock(return_value={'id': rid})
        obj.guard_group_children, obj.verify_fixture = Mock(), Mock()
        obj.local_backend_check = Mock()
        obj.inventory(persist=False)
        prior = dict(obj.inventory_receipt)
        prior['persistent_resource_ids'] = {}
        lifecycle.save_json(obj.state / 'run-manifest.json', prior)
        obj.persistent, obj.namespace_uid = {}, None
        return obj, prior

    def test_exact_corruption_recovery_preserves_private_snapshot(self):
        obj, prior = self.recovery_setup()
        path = obj.state / 'run-manifest.json'
        before = path.read_bytes()
        states = {p: p.read_bytes() for p in obj.state.glob('*.tfstate')}
        result = obj.recover_manifest()
        backup = Path(result['backup'])
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual({p: p.read_bytes() for p in states}, states)
        self.assertEqual(json.loads(path.read_text()), dict(prior, persistent_resource_ids=obj.persistent))
        obj.verify_fixture.assert_called_once_with()

    def test_corruption_recovery_rejects_unknown_wrong_uid_and_ids(self):
        for defect in ('unknown', 'uid', 'id', 'state', 'receipt'):
            with self.subTest(defect=defect):
                obj, prior = self.recovery_setup()
                path = obj.state / 'run-manifest.json'
                if defect == 'unknown':
                    prior['unknown'] = True
                elif defect == 'uid':
                    prior['xc_preserved'][0]['uid'] = 'wrong'
                elif defect == 'id':
                    prior['owned_resources'][0]['id'] = 'wrong'
                elif defect == 'state':
                    lifecycle.save_json(obj.state / 'namespace.tfstate', {'resources': []})
                else:
                    lifecycle.save_json(obj.state / 'namespace-receipt.json', {'path': 'wrong', 'uid': 'wrong'})
                lifecycle.save_json(path, prior)
                before = path.read_bytes()
                with self.assertRaises(lifecycle.Blocked):
                    obj.recover_manifest()
                self.assertEqual(path.read_bytes(), before)


    def test_readonly_inventory_never_writes_manifest(self):
        obj, _ = self.recovery_setup()
        obj.persistent, obj.namespace_uid = obj.foundation_proof()
        path = obj.state / 'run-manifest.json'
        before = path.read_bytes()
        obj.inventory(persist=False)
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaisesRegex(lifecycle.Blocked, 'existing run foundation incompatible'):
            obj.inventory()
        self.assertEqual(path.read_bytes(), before)

    def test_recovery_wrong_live_uid_never_writes(self):
        obj, _ = self.recovery_setup()
        obj.xc.return_value['system_metadata']['uid'] = 'changed'
        path = obj.state / 'run-manifest.json'
        before = path.read_bytes()
        with self.assertRaisesRegex(lifecycle.Blocked, 'UID identity mismatch'):
            obj.recover_manifest()
        self.assertEqual(path.read_bytes(), before)

    def test_deploy_and_rebuild_keep_corruption_guard(self):
        obj, _ = self.recovery_setup()
        for operation in ('deploy', 'rebuild'):
            obj.operation = operation
            with self.assertRaisesRegex(lifecycle.Blocked, 'existing run foundation incompatible'):
                obj.namespace_prepare()


    def test_inventory_retains_only_external_namespace(self):
        obj = self.instance
        base = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/'
        obj.persistent = {'namespace': 'system/' + lifecycle.FIXED['namespace']}
        obj.namespace_uid = 'uid-' + lifecycle.FIXED['namespace']
        obj.foundation_proof = Mock()
        resources = [
            {'mode': 'managed', 'type': 'azurerm_resource_group', 'address': 'rg.main', 'values': {'id': base + 'application', 'name': 'application'}},
            {'mode': 'managed', 'type': 'xcsh_origin_pool', 'address': 'pool.main', 'values': {'id': 'pool-id', 'name': 'origin-pool', 'namespace': lifecycle.FIXED['namespace']}},
        ]
        obj.tf = Mock(return_value=(json.dumps({'values': {'root_module': {'resources': resources}}}), 0))
        obj.xc = Mock(side_effect=lambda path: {'metadata': {'name': path.rsplit('/', 1)[-1]}, 'system_metadata': {'uid': 'uid-' + path.rsplit('/', 1)[-1]}})
        obj.azure_api_versions = Mock(side_effect=lambda ids: {rid: '2024-01-01' for rid in ids})
        self.assertEqual(obj.inventory(), {'rg.main': base + 'application', 'pool.main': 'pool-id'})
        manifest = json.loads((obj.state / 'run-manifest.json').read_text())
        self.assertEqual(manifest['azure_preserved'], [])
        self.assertEqual(manifest['persistent_resource_ids'], obj.persistent)
        self.assertEqual(manifest['xc_preserved'][0]['path'], '/api/web/namespaces/' + lifecycle.FIXED['namespace'])
        self.assertEqual(set(manifest['azure_api_versions']), set(manifest['azure_owned'] + manifest['azure_preserved']))


    def test_fixture_preservation_checks_real_canonical_readback(self):
        obj = self.instance
        obj.root = Path(__file__).resolve().parents[1]
        pinned = '/api/object_store/namespaces/webapp-api-protection/stored_objects/swagger/showcase/v1'
        receipt = {'api_url': lifecycle.FIXED['xc_url'], 'namespace': lifecycle.FIXED['namespace'], 'name': 'showcase', 'path': pinned, 'version': 'v1', 'content': '{"openapi":"3.0.3"}'}
        lifecycle.save_json(obj.state / 'swagger-receipt.json', receipt)
        lifecycle.save_json(obj.vars, {'api_definition_swagger_specs': [pinned]})
        obj.xc = Mock(return_value={'metadata': {'name': 'showcase', 'namespace': lifecycle.FIXED['namespace'], 'version': 'v1'}, 'string_value': receipt['content']})
        obj.verify_fixture()
        obj.xc.assert_called_once_with(pinned)
        obj.xc.return_value['string_value'] = '{}'
        with self.assertRaisesRegex(lifecycle.Blocked, 'content/version'):
            obj.verify_fixture()

    def test_missing_fixture_receipt_never_uploads(self):
        obj = self.instance
        obj.xc = Mock()
        obj.run = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'receipt missing'):
            obj.verify_fixture()
        obj.xc.assert_not_called()
        obj.run.assert_not_called()




class ReviewedDefects(unittest.TestCase):
    setUp = Orchestration.setUp

    def test_rebuild_missing_write_destroys_nothing(self):
        obj = self.instance
        obj.operation = 'rebuild'
        obj.az = Mock(return_value={'value': [{'actions': ['*'], 'notActions': ['Microsoft.Compute/virtualMachines/write']}]})
        obj.preflight = lambda deploying: obj.capacity_permissions() if deploying else None
        obj.destroy = Mock()
        obj.deploy = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'Microsoft.Compute/virtualMachines/write'):
            obj.execute()
        obj.destroy.assert_not_called()
        obj.deploy.assert_not_called()

    def prepare_capacity(self, allocated=True):
        obj = self.instance
        obj.operation = 'rebuild'
        obj.namespace_prepare = Mock()
        obj.app_init = Mock()
        obj.inventory = Mock()
        obj.verify_fixture = Mock()
        obj.get_outputs = Mock()
        obj.verify_phase = Mock()
        lifecycle.save_json(obj.vars, {})
        base = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/owned/providers/Microsoft.Compute/virtualMachines/'
        obj.resources = [{'type': 'azurerm_linux_virtual_machine', 'values': {'id': base + str(i), 'size': size}}
                         for i, size in enumerate(('Standard_D16s_v3', 'Standard_F16s_v2'))]
        def az(*args):
            if args[0] == 'rest':
                return {'value': [{'actions': ['*'], 'notActions': []}]}
            if args[1] == 'show':
                item = next(r for r in obj.resources if r['values']['id'] == args[3])
                return {'id': args[3], 'location': 'eastus2', 'hardwareProfile': {'vmSize': item['values']['size']},
                        'powerState': 'VM running' if allocated else 'VM deallocated'}
            if args[1] == 'list-usage':
                return [{'name': {'value': name}, 'limit': count, 'currentValue': count, 'unit': 'Count'}
                        for name, count in [('cores', 32), ('standarddsv3family', 16), ('standardfsv2family', 16)]]
            return [{'name': size, 'restrictions': []} for size in ('Standard_D16s_v3', 'Standard_F16s_v2')]
        obj.az = Mock(side_effect=az)
        return obj

    def test_live_shape_string_quotas_pass_deploy(self):
        obj = self.prepare_capacity()
        obj.operation = 'deploy'
        previous = obj.az.side_effect
        def az(*args):
            if args[:2] == ('vm', 'list-usage'):
                return [{'name': {'value': name}, 'currentValue': current, 'limit': limit, 'unit': 'Count'}
                        for name, current, limit in [('cores', '52', '362'),
                                                    ('standardDSv3Family', '0', '350'),
                                                    ('standardFSv2Family', '0', '350')]]
            return previous(*args)
        obj.az.side_effect = az
        obj.capacity_permissions()
        obj.inventory.assert_not_called()
        self.assertIn('azure-permissions-quota-skus', [p['name'] for p in obj.receipt['phases']])

    def test_quota_counts_normalize_exact_nonnegative_numbers(self):
        for value in (0, 32, 32.0, '0', '32', 2 ** 53 - 1, str(2 ** 53 - 1)):
            with self.subTest(value=value):
                self.assertEqual(lifecycle.quota_count(value), int(value))

    def test_malformed_quota_counts_fail_blocked(self):
        invalid = (None, True, False, -1, '-1', 1.5, '1.5', '', ' 32', '+32',
                   '１２', '1e3', float('nan'), float('inf'), -float('inf'),
                   2 ** 53, str(2 ** 53), '9' * 5000, [], {})
        for field in ('currentValue', 'limit'):
            for value in invalid:
                with self.subTest(field=field, value=str(value)[:32]):
                    obj = self.prepare_capacity()
                    previous = obj.az.side_effect
                    def az(*args):
                        result = previous(*args)
                        if args[:2] == ('vm', 'list-usage'):
                            result[0][field] = value
                        return result
                    obj.az.side_effect = az
                    with self.assertRaisesRegex(lifecycle.Blocked, 'malformed.*quota'):
                        obj.capacity_permissions()

    def test_missing_duplicate_or_unknown_unit_quotas_fail_blocked(self):
        for mode in ('missing', 'duplicate', 'unknown-unit', 'missing-unit', 'shape'):
            with self.subTest(mode=mode):
                obj = self.prepare_capacity()
                previous = obj.az.side_effect
                def az(*args):
                    result = previous(*args)
                    if args[:2] == ('vm', 'list-usage'):
                        if mode == 'missing':
                            return result[1:]
                        if mode == 'duplicate':
                            return result + [result[0]]
                        if mode == 'shape':
                            return {}
                        result[0]['unit'] = 'VMs' if mode == 'unknown-unit' else None
                    return result
                obj.az.side_effect = az
                with self.assertRaisesRegex(lifecycle.Blocked, 'eastus2 VM quota'):
                    obj.capacity_permissions()


    def test_no_role_or_storage_access_required(self):
        obj = self.prepare_capacity()
        previous = obj.az.side_effect
        def az(*args):
            if args[:3] == ('rest', '--method', 'get') and '/permissions?' in args[-1]:
                return {'value': [{'actions': ['*'], 'notActions': [
                    'Microsoft.Authorization/roleAssignments/write', 'Microsoft.Storage/*']}]}
            return previous(*args)
        obj.az = Mock(side_effect=az)
        obj.capacity_permissions()
        obj.verify_phase.assert_not_called()
        obj.get_outputs.assert_not_called()
        self.assertTrue(all('storage' not in c.args and 'Microsoft.Storage' not in str(c.args) for c in obj.az.call_args_list))

    def test_owned_unhealthy_rebuild_keeps_ownership_guards_and_can_repair(self):
        obj = self.prepare_capacity()
        obj.preflight = lambda deploying: obj.capacity_permissions()
        obj.verify_phase.side_effect = lifecycle.Blocked('not ready')
        obj.get_outputs.side_effect = lifecycle.Blocked('missing showcase')
        obj.destroy = Mock()
        obj.deploy = Mock()
        obj.execute()
        obj.destroy.assert_called_once_with()
        obj.deploy.assert_called_once_with()
        obj.namespace_prepare.assert_called_once_with()
        obj.inventory.assert_called_once_with()
        obj.verify_fixture.assert_called_once_with()
        obj.verify_phase.assert_not_called()
        obj.get_outputs.assert_not_called()

    def test_unhealthy_rebuild_does_not_skip_ownership_failure(self):
        obj = self.prepare_capacity()
        obj.preflight = lambda deploying: obj.capacity_permissions()
        obj.inventory.side_effect = lifecycle.Blocked('unowned group child')
        obj.verify_phase.side_effect = lifecycle.Blocked('not ready')
        obj.destroy = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'unowned group child'):
            obj.execute()
        obj.destroy.assert_not_called()


    def test_rebuild_credits_only_exact_owned_allocated_cores(self):
        obj = self.prepare_capacity()
        obj.capacity_permissions()
        obj.namespace_prepare.assert_called_once_with()
        obj.inventory.assert_called_once()
        obj.verify_fixture.assert_called_once()

    def test_deploy_still_requires_32_free_cores(self):
        obj = self.prepare_capacity()
        obj.operation = 'deploy'
        with self.assertRaisesRegex(lifecycle.Blocked, 'VM quota'):
            obj.capacity_permissions()
        obj.inventory.assert_not_called()

    def test_owned_credit_rejects_live_identity_mismatch(self):
        obj = self.prepare_capacity()
        previous = obj.az.side_effect
        def az(*args):
            value = previous(*args)
            if args[:2] == ('vm', 'show'):
                value['id'] = 'unowned'
            return value
        obj.az.side_effect = az
        with self.assertRaisesRegex(lifecycle.Blocked, 'identity/SKU mismatch'):
            obj.capacity_permissions()


    def test_deallocated_owned_vms_do_not_release_quota(self):
        obj = self.prepare_capacity(False)
        with self.assertRaisesRegex(lifecycle.Blocked, 'VM quota'):
            obj.capacity_permissions()

    def test_rebuild_sku_failure_precedes_destroy(self):
        obj = self.prepare_capacity()
        previous = obj.az.side_effect
        obj.az.side_effect = lambda *a: [] if a[:2] == ('vm', 'list-skus') else previous(*a)
        obj.preflight = lambda deploying: obj.capacity_permissions()
        obj.destroy = Mock()
        with self.assertRaisesRegex(lifecycle.Blocked, 'SKU unavailable'):
            obj.execute()
        obj.destroy.assert_not_called()

    def test_partial_apply_destroy_uses_inventory_not_showcase_output(self):
        obj = self.instance
        obj.operation = 'destroy'
        obj.namespace_prepare = Mock()
        obj.namespace_tf_prepare = Mock()
        obj.app_init = Mock()
        lifecycle.save_json(obj.vars, {})
        obj.get_outputs = Mock(side_effect=lifecycle.Blocked('missing showcase'))
        obj.resources = [{'type': 'azurerm_resource_group', 'address': 'group.main', 'values': {'id': 'owned'}}]
        obj.inventory = Mock(return_value={'group.main': 'owned'})
        obj.traffic = Mock()
        obj.plan = Mock(return_value=obj.state / 'destroy.plan')
        obj.tf = Mock(side_effect=[('', 0), ('{"values":{"root_module":{}}}', 0), ('', 0)])
        obj.verify_phase = Mock()
        obj.verify_fixture = Mock()
        obj.destroy()
        obj.get_outputs.assert_not_called()
        obj.plan.assert_called_once_with('destroy', 'destroy', {'group.main': 'owned'})
        obj.verify_phase.assert_called_once_with('absence')
        self.assertIsNone(obj.outputs)

    def test_unknown_generator_state_does_not_prove_absence(self):
        with self.assertRaisesRegex(lifecycle.Blocked, 'ownership state incomplete'):
            self.instance.cleanup_access([{'address': 'module.traffic_generator.unknown', 'values': {}}])


    def test_generator_partial_access_fails_closed(self):
        obj = self.instance
        resources, _ = SSHEnrollment.guest_state('generator')
        with self.assertRaisesRegex(lifecycle.Blocked, 'public_ip unavailable'):
            obj.cleanup_access(resources[:-1])
        self.assertIsNone(obj.outputs)

    def test_generator_cleanup_requires_live_state_owned_access(self):
        obj = self.instance
        resources, guest = SSHEnrollment.guest_state('generator')
        obj.az = Mock(return_value=SSHEnrollment.live_vm(resources, guest))
        obj.cleanup_access(resources)
        obj.run = Mock(return_value=('', 0))
        obj.traffic('stop')
        calls = [call.args[0] for call in obj.run.call_args_list]
        self.assertEqual(len(calls), 2)
        self.assertIn('StrictHostKeyChecking=accept-new', calls[0])
        self.assertEqual(calls[0][-1], 'true')
        self.assertIn('StrictHostKeyChecking=yes', calls[1])
        self.assertIn('azureuser@192.0.2.1', calls[1])
        obj.az.return_value['id'] = 'unowned'
        with self.assertRaisesRegex(lifecycle.Blocked, 'ownership/access mismatch'):
            obj.cleanup_access(resources)



    def test_slow_drip_response_obeys_total_deadline(self):
        obj = self.instance
        obj.env['XCSH_API_TOKEN'] = 'test'
        obj.deadline = time.monotonic() + .015
        sock = Mock()
        response = Mock()
        response.fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))
        response.length = None
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        def drip(*args):
            time.sleep(.02)
            return b' '
        response.read1.side_effect = drip
        obj.opener = Mock()
        obj.opener.open.return_value = response
        with self.assertRaisesRegex(lifecycle.Blocked, 'deadline exceeded'):
            obj.xc('/test')
        response.read.assert_not_called()
        sock.settimeout.assert_called_once()

    def test_real_http_slow_body_cannot_extend_deadline(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class SlowBody(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '100')
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b' ')
                        self.wfile.flush()
                        time.sleep(.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), SlowBody)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            obj = self.instance
            obj.env['XCSH_API_TOKEN'] = 'test'
            obj.deadline = time.monotonic() + .08
            start = time.monotonic()
            with patch.dict(obj.scope, xc_url='http://127.0.0.1:' + str(server.server_port)):
                with self.assertRaises(lifecycle.Blocked):
                    obj.xc('/slow')
            self.assertLess(time.monotonic() - start, .5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_empty_application_state_never_proves_ownership(self):
        obj = self.instance
        obj.persistent = {'namespace': 'system/' + lifecycle.FIXED['namespace']}
        obj.namespace_uid = 'uid'
        obj.foundation_proof = Mock()
        obj.tf = Mock(return_value=('{}', 0))
        with self.assertRaisesRegex(lifecycle.Blocked, 'missing application state'):
            obj.inventory()


    def test_truncated_response_is_not_accepted(self):
        obj = self.instance
        obj.env['XCSH_API_TOKEN'] = 'test'
        response = Mock()
        response.fp = SimpleNamespace(raw=SimpleNamespace(_sock=Mock()))
        response.length = 10
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read1.side_effect = [b'{}', b'']
        obj.opener.open = Mock(return_value=response)
        with self.assertRaisesRegex(lifecycle.Blocked, 'truncated XC response'):
            obj.xc('/test')




class SSHEnrollment(unittest.TestCase):
    setUp = Orchestration.setUp

    @staticmethod
    def guest_state(role):
        module = {'origin': 'origin_server', 'generator': 'traffic_generator'}[role]
        prefix = 'module.' + module + '.'
        base = '/subscriptions/' + TEST_SCOPE['subscription_id'] + '/resourceGroups/' + module + '/providers/'
        vm_id = base + 'Microsoft.Compute/virtualMachines/main'
        nic_id = base + 'Microsoft.Network/networkInterfaces/main'
        pip_id = base + 'Microsoft.Network/publicIPAddresses/main'
        guest = {'id': vm_id, 'admin_username': 'azureuser',
                 'public_ip': '192.0.2.1' if role == 'generator' else '192.0.2.2'}
        values = [('linux_virtual_machine', dict(id=vm_id, admin_username='azureuser', network_interface_ids=[nic_id])),
                  ('network_interface', dict(id=nic_id, ip_configuration=[{'public_ip_address_id': pip_id}])),
                  ('public_ip', dict(id=pip_id, ip_address=guest['public_ip']))]
        return [{'type': 'azurerm_' + kind, 'address': prefix + 'azurerm_' + kind + '.main', 'values': v}
                for kind, v in values], guest

    @staticmethod
    def live_vm(resources, guest):
        return {'id': guest['id'], 'osProfile': {'adminUsername': guest['admin_username']},
                'publicIps': guest['public_ip'],
                'networkProfile': {'networkInterfaces': [{'id': resources[1]['values']['id']}]}}

    def prepare(self):
        obj = self.instance
        obj.resources = []
        obj.outputs = {'namespace': lifecycle.FIXED['namespace']}
        live = {}
        for role in ('origin', 'generator'):
            resources, guest = self.guest_state(role)
            obj.resources.extend(resources)
            obj.outputs[role] = guest
            live[guest['id']] = self.live_vm(resources, guest)
        obj.az = Mock(side_effect=lambda *args: live[args[3]])
        obj.run = Mock(return_value=('', 0))
        return obj, live

    def test_both_fresh_hosts_enrolled_before_strict_readiness(self):
        obj, _ = self.prepare()
        obj.verify_phase('readiness')
        calls = [c.args[0] for c in obj.run.call_args_list]
        self.assertEqual(len(calls), 3)
        for role, argv in zip(('origin', 'generator'), calls[:2]):
            self.assertIn('StrictHostKeyChecking=accept-new', argv)
            self.assertIn('UserKnownHostsFile=' + str(obj.known_hosts), argv)
            self.assertEqual(argv[-2:], ['azureuser@' + obj.outputs[role]['public_ip'], 'true'])
        self.assertEqual(calls[2][0], 'bash')
        self.assertIn('--known-hosts', calls[2])
        verifier = (Path(__file__).resolve().parents[1] / 'scripts/demo_verify.py').read_text()
        self.assertIn('StrictHostKeyChecking=yes', verifier)

    def test_changed_key_and_dead_guest_never_reach_verifier(self):
        for failure in (lifecycle.Blocked('ssh changed host key exit 255'), subprocess.TimeoutExpired('ssh', 10)):
            with self.subTest(failure=type(failure).__name__):
                obj, _ = self.prepare()
                obj.run.side_effect = failure
                with self.assertRaises(type(failure)):
                    obj.verify_phase('readiness')
                self.assertEqual(obj.run.call_count, 1)
                self.assertNotIn('live-readiness', [p['name'] for p in obj.receipt['phases']])

    def test_all_destinations_guarded_before_first_connection(self):
        for defect in ('output-ip', 'output-id', 'output-user', 'subscription', 'nic-join', 'pip-join', 'live-id', 'live-ip', 'live-user', 'live-nic', 'namespace'):
            with self.subTest(defect=defect):
                obj, live = self.prepare()
                guest = obj.outputs['generator']
                if defect.startswith('output-'):
                    guest[{'output-ip': 'public_ip', 'output-id': 'id', 'output-user': 'admin_username'}[defect]] = 'foreign'
                elif defect == 'subscription':
                    obj.resources[-1]['values']['id'] = obj.resources[-1]['values']['id'].replace(TEST_SCOPE['subscription_id'], 'foreign')
                elif defect == 'nic-join':
                    obj.resources[3]['values']['network_interface_ids'] = ['foreign']
                elif defect == 'pip-join':
                    obj.resources[4]['values']['ip_configuration'][0]['public_ip_address_id'] = 'foreign'
                elif defect == 'namespace':
                    obj.outputs['namespace'] = 'foreign'
                else:
                    vm = live[guest['id']]
                    if defect == 'live-id':
                        vm['id'] = 'foreign'
                    elif defect == 'live-ip':
                        vm['publicIps'] = '192.0.2.99'
                    elif defect == 'live-user':
                        vm['osProfile']['adminUsername'] = 'foreign'
                    else:
                        vm['networkProfile']['networkInterfaces'][0]['id'] = 'foreign'
                with self.assertRaises(lifecycle.Blocked):
                    obj.verify_phase('readiness')
                obj.run.assert_not_called()

    def test_enrollment_failure_cleanup_preserves_original_error(self):
        obj, _ = self.prepare()
        obj.preflight = Mock()
        obj.deploy = lambda: obj.verify_phase('readiness')
        obj.run.side_effect = lifecycle.Blocked('ssh changed host key exit 255')
        with self.assertRaisesRegex(lifecycle.Blocked, 'changed host key'):
            obj.execute()
        self.assertEqual(obj.receipt['status'], 'blocked')
        self.assertEqual(obj.receipt['error'], 'ssh changed host key exit 255')
        self.assertIn('original failure retained', obj.receipt['cleanup'])
        self.assertFalse(any(c.args[0][0] == 'bash' for c in obj.run.call_args_list))

    def test_enrollment_deadline_is_bounded_and_restored_on_timeout(self):
        obj, _ = self.prepare()
        original = time.monotonic() + 1800
        obj.deadline = original
        def timeout(*args):
            self.assertLessEqual(obj.remaining(), 20)
            raise subprocess.TimeoutExpired('ssh', 20)
        obj.run.side_effect = timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            obj.enroll_guests()
        self.assertEqual(obj.deadline, original)

    def test_dead_guest_failure_survives_failed_stop(self):
        obj, _ = self.prepare()
        obj.preflight = Mock()
        obj.deploy = lambda: obj.verify_phase('readiness')
        failure = subprocess.TimeoutExpired('ssh', 20)
        obj.run.side_effect = failure
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            obj.execute()
        self.assertIs(caught.exception, failure)
        self.assertEqual(obj.receipt['error'], 'TimeoutExpired')
        self.assertIn('original failure retained', obj.receipt['cleanup'])

    def test_wrong_config_cannot_authorize_cleanup_ssh(self):
        obj, _ = self.prepare()
        obj.config['namespace'] = 'foreign'
        with self.assertRaisesRegex(lifecycle.Blocked, 'configuration scope'):
            obj.traffic('stop')
        obj.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
