"""Deterministic bookkeeping/failure tests, never live security acceptance."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import urllib.parse
import tempfile
from unittest import mock

SPEC = importlib.util.spec_from_file_location('demo_traffic', Path(__file__).resolve().parents[1] / 'scripts/demo_traffic.py')
traffic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(traffic)


def rendered_cloud_config(domains, tier='standard'):
    import yaml
    root = Path(__file__).resolve().parents[1]
    template = (root / 'terraform/cloud-init/traffic-generator.yaml').read_text()
    script = (root / 'scripts/demo_traffic.py').read_text()
    substitutions = {'target_domains': json.dumps(domains), 'target_origin_ip': '192.0.2.1',
                     'tool_tier': tier, 'mud_bad_traffic': 'true',
                     'traffic_script': script.replace('\n', '\n      ').rstrip()}
    for key, value in substitutions.items():
        template = template.replace('${' + key + '}', value)
    template = template.replace('$${', '${').replace('%%{', '%{')
    return template, yaml.safe_load(template)



def captured_echo(target):
    """Sanitized owned 1138b519 capture shape; synthetic identities, not live proof."""
    url = urllib.parse.urlsplit(target['url'])
    body = {'method': target['method'],
            'url': urllib.parse.urlunsplit(url._replace(path=url.path.removeprefix('/httpbin'))),
            'headers': {'Host': url.hostname, 'X-Mud-User': target['header']['X-MUD-User'][0]}}
    return base64.b64encode(json.dumps(body).encode()).decode()


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.domains = ['www.f5-sales-demo.com', 'api.f5-sales-demo.com']
        self.targets = traffic.targets(self.domains, 'fresh-run', 0)
        self.records = []
        for target in self.targets:
            url = urllib.parse.urlsplit(target['url'])
            cls = urllib.parse.parse_qs(url.query)['demo_class'][0]
            self.records.append({'domain': url.hostname, 'class': cls, 'code': 200 if cls == 'benign' else (429 if cls == 'rate-limit' else 403), 'error': '', 'url': target['url'], 'method': target['method'], 'body': captured_echo(target)})
        self.report = {'requests': 1500, 'rate': 50, 'duration': 30_000_000_000, 'latencies': {'min': 1, 'mean': 5, '50th': 5, '90th': 6, '95th': 7, '99th': 8, 'max': 10}, 'errors': []}

    def configuration(self):
        return {'target_domains': self.domains, 'target_origin_ip': '192.0.2.1',
                'tool_tier': 'standard', 'mud_bad_traffic': True}

    def test_invalid_complete_profile_never_authorizes_starts_or_calls_network(self):
        cases = [('mud_bad_traffic', False), ('mud_bad_traffic', 'true'),
                 ('target_domains', self.domains[:1]), ('target_domains', self.domains * 2),
                 ('target_domains', [self.domains[0], 'api.example.com/SECRET']),
                 ('target_domains', [self.domains[0], '-bad.example.com']),
                 ('target_domains', [self.domains[0], None]),
                 ('target_origin_ip', '127.0.0.1'), ('target_origin_ip', 'SECRET'),
                 ('tool_tier', 'unknown'), ('rate', 100)]
        for key, value in cases:
            bad = dict(self.configuration(), **{key: value})
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(traffic, 'ROOT', Path(directory)), \
                    mock.patch.object(traffic, 'config', return_value=bad), \
                    mock.patch.object(traffic.subprocess, 'run') as run, \
                    mock.patch.object(traffic.urllib.request, 'build_opener') as network, \
                    mock.patch.object(traffic.sys, 'argv', ['tgen-control', 'start']):
                with self.assertRaises(traffic.ConfigurationError) as error:
                    traffic.main()
                self.assertNotIn('SECRET', str(error.exception))
                run.assert_not_called()
                network.assert_not_called()
                self.assertFalse((Path(directory) / 'authorization.json').exists())

    def test_prestart_exercises_canonical_targets_before_tools(self):
        with mock.patch.object(traffic, 'targets', side_effect=ValueError('SECRET')) as targets, \
                mock.patch.object(traffic.subprocess, 'run') as run:
            with self.assertRaisesRegex(traffic.ConfigurationError, '^invalid_configuration$'):
                traffic.cheap_ready(self.configuration())
            targets.assert_called_once_with(self.domains, 'configuration-check', 0, True)
            run.assert_not_called()

    def test_configuration_failure_persists_safe_scheduled_history(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), \
                mock.patch.object(traffic.subprocess, 'run') as run:
            value = dict(self.configuration(), mud_bad_traffic=False)
            self.assertEqual(traffic.run_cycle(value, 'scheduled'), 1)
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['error_class'], 'configuration')
            self.assertEqual(status['error_stage'], 'configuration')
            self.assertEqual(status['failures'], ['mud_bad_traffic_required'])
            self.assertNotIn('count', status)
            self.assertEqual(status['history'][0]['status'], 'failed')
            run.assert_not_called()

    def test_malformed_json_scheduled_attempt_records_failure(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), \
                mock.patch.object(traffic, 'config', side_effect=ValueError('SECRET')), \
                mock.patch.object(traffic.sys, 'argv', ['tgen-control', 'scheduled']):
            self.assertEqual(traffic.main(), 1)
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['error_class'], 'configuration')
            self.assertNotIn('SECRET', json.dumps(status))

    def test_readiness_failure_preserves_history_after_stop(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), \
                mock.patch.object(traffic, 'cheap_ready', side_effect=FileNotFoundError('SECRET')), \
                mock.patch.object(traffic.subprocess, 'run') as run:
            value = self.configuration()
            traffic.atomic(Path(directory) / 'authorization.json', {'config_sha256': traffic.fingerprint(value)})
            self.assertEqual(traffic.run_cycle(value, 'scheduled'), 1)
            with mock.patch.object(traffic.sys, 'argv', ['tgen-control', 'stop']):
                self.assertEqual(traffic.main(), 0)
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['error_class'], 'tool_missing')
            self.assertEqual(status['error_stage'], 'readiness')
            self.assertEqual(status['history'][0]['status'], 'failed')
            self.assertNotIn('SECRET', json.dumps(status))

    def test_missing_metrics_are_failed_not_zero_and_never_echo_tool_output(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), \
                mock.patch.object(traffic, 'cheap_ready'), \
                mock.patch.object(traffic.subprocess, 'run', side_effect=[
                    subprocess.CompletedProcess(['vegeta', 'attack'], 0),
                    subprocess.CalledProcessError(1, ['vegeta', 'report'], output='SECRET')]):
            value = self.configuration()
            traffic.atomic(Path(directory) / 'authorization.json', {'config_sha256': traffic.fingerprint(value)})
            self.assertEqual(traffic.run_cycle(value, 'scheduled'), 1)
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['error_class'], 'metrics_unavailable')
            self.assertEqual(status['error_stage'], 'metrics')
            self.assertNotIn('count', status)
            self.assertNotIn('SECRET', json.dumps(status))

    def test_real_decoder_and_targets_bookkeeping_1499_to_1501(self):
        # Fixtures test only decoding/accounting; they make no live security claim.
        for count in (1499, 1500, 1501):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(traffic, 'ROOT', Path(directory)), \
                    mock.patch.object(traffic, 'cheap_ready'):
                root = Path(directory)
                value = self.configuration()
                traffic.atomic(root / 'authorization.json', {'config_sha256': traffic.fingerprint(value)})
                def tool(argv, **kwargs):
                    if argv[1] == 'report':
                        report = dict(self.report, requests=count, rate=count / 30, errors=['403 Forbidden', '429 Too Many Requests'])
                        json.dump(report, kwargs['stdout'])
                    if argv[1] == 'encode':
                        folder = Path(argv[-1]).parent
                        target_list = [json.loads(line) for line in (folder / 'targets.jsonl').read_text().splitlines()]
                        for i in range(count):
                            target = target_list[i % 1500]
                            cls = target['header']['X-Demo-Class'][0]
                            code = 200 if cls == 'benign' else 429 if cls == 'rate-limit' else 403
                            item = {'url': target['url'], 'code': code, 'method': target['method'], 'body': captured_echo(target),
                                    'error': '' if code == 200 else f'{code} {traffic.responses[code]}',
                                    'timestamp': '2026-10-01T00:00:00Z', 'latency': 5}
                            kwargs['stdout'].write(json.dumps(item) + '\n')
                    return subprocess.CompletedProcess(argv, 0)
                with mock.patch.object(traffic.subprocess, 'run', side_effect=tool) as run:
                    self.assertEqual(traffic.run_cycle(value, 'scheduled'), 0)
                status = json.loads((root / 'status.json').read_text())
                self.assertEqual(status['count'], count)
                self.assertEqual(status['rate'], count / 30)
                self.assertEqual(status['duration_seconds'], 30)
                self.assertEqual(status['class_counts']['benign'], 1350 - max(0, 1500 - count))
                self.assertEqual(status['transport_errors'], 0)
                self.assertEqual(status['http_errors'], 150 + max(0, count - 1500))
                self.assertEqual(status['response_failures'], 0)
                self.assertEqual(status['failures'], [])
                attack = run.call_args_list[0].args[0]
                self.assertIn('-rate=50/s', attack)
                self.assertIn('-duration=30s', attack)


    def test_scheduled_pressure_is_measurement_not_required_rate_proof(self):
        bad = [{**r, 'code': 403} if r['class'] == 'rate-limit' else r for r in self.records]
        self.assertIn('unexpected_response', traffic.evaluate(self.report, bad, self.domains))
        valid = copy.deepcopy(self.records)
        for row in valid:
            if row['class'] in ('rate-limit', 'mud'):
                row['code'] = 200
        for domain in self.domains:
            next(row for row in valid if row['domain'] == domain and row['class'] == 'rate-limit')['code'] = 429
        self.assertEqual(traffic.evaluate(self.report, valid, self.domains), [])


    def test_rate_200_requires_actual_decodable_origin_echo(self):
        records = copy.deepcopy(self.records)
        row = records[0]
        row['code'] = 200
        for body in (None, '', 'not base64', base64.b64encode(b'Forbidden').decode(),
                     base64.b64encode(b'{}').decode()):
            row['body'] = body
            self.assertIn('rate_origin_response_unconfirmed', traffic.evaluate(self.report, records, self.domains))
        original = json.loads(base64.b64decode(self.records[0]['body']))
        for field, value in (('method', 'POST'), ('url', 'http://other.example/anything/rate-limit'),
                             ('headers', {'Host': row['domain'], 'X-Mud-User': 'other-user'}),
                             ('headers', {'Host': 'other.example', 'X-Mud-User': 'rate-limit-fresh-run'})):
            body = {**original, field: value}
            row['body'] = base64.b64encode(json.dumps(body).encode()).decode()
            self.assertIn('rate_origin_response_unconfirmed', traffic.evaluate(self.report, records, self.domains))
        row['body'] = self.records[0]['body']
        self.assertEqual(traffic.evaluate(self.report, records, self.domains), [])


    def test_synthetic_bookkeeping(self):
        self.assertEqual([], traffic.evaluate(self.report, self.records, self.domains))

    def test_frontloaded_aggregate_budget(self):
        for sequence in (0, 1, 2, 14, 15):
            targets = traffic.targets(self.domains, f'fresh-{sequence}', sequence)
            self.assertEqual(len(targets), 1500)
            self.assertEqual([t['header']['X-Demo-Class'][0] for t in targets[:50]], ['rate-limit'] * 50)
            self.assertEqual([urllib.parse.urlsplit(t['url']).hostname for t in targets[:50]], self.domains * 25)
            self.assertEqual((50 - 1) / 50, .98)  # Intended pacing, not observed timing.
            self.assertTrue(all(t['header']['X-Demo-Class'] != ['rate-limit'] for t in targets[50:]))
            for domain in self.domains:
                subset = [t for t in targets if urllib.parse.urlsplit(t['url']).hostname == domain]
                classes = [t['header']['X-Demo-Class'][0] for t in subset]
                self.assertEqual(len(subset), 750)
                self.assertEqual(classes.count('benign'), 675)
                self.assertEqual(classes.count('rate-limit'), 25)
                self.assertEqual(set(classes), {'benign', *traffic.CLASSES})
                self.assertEqual({t['header']['X-MUD-User'][0] for t in subset if t['header']['X-Demo-Class'] == ['rate-limit']}, {f'rate-limit-fresh-{sequence}'})
                identities = {cls: {t['header']['X-MUD-User'][0] for t in subset if t['header']['X-Demo-Class'] == [cls]} for cls in set(classes)}
                for cls, ids in identities.items():
                    for other, other_ids in identities.items():
                        if cls != other:
                            self.assertFalse(ids & other_ids)
            self.assertEqual({urllib.parse.urlsplit(t['url']).hostname for t in targets}, set(self.domains))

    def test_decoded_scheduled_capture_preserves_failed_history(self):
        # Full decoder path with captured aggregate outcomes; no live traffic.
        for case in ('rate_refill', 'fresh_rate', 'missing_body', 'blocking_page', 'wrong_identity', 'rate_403', 'network', 'aggregate_extra', 'business'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(traffic, 'ROOT', Path(directory)), \
                    mock.patch.object(traffic, 'cheap_ready'):
                root = Path(directory)
                value = self.configuration()
                traffic.atomic(root / 'authorization.json', {'config_sha256': traffic.fingerprint(value)})
                def tool(argv, **kwargs):
                    if argv[1] == 'report':
                        errors = ['403 Forbidden']
                        if case not in ('rate_refill', 'missing_body', 'blocking_page', 'wrong_identity', 'rate_403'):
                            errors.append('429 Too Many Requests')
                        if case == 'network':
                            errors.append('read timeout')
                        if case == 'business':
                            errors.append('500 Internal Server Error')
                        if case == 'aggregate_extra':
                            errors.append('unrelated aggregate error')
                        json.dump({**self.report, 'errors': errors}, kwargs['stdout'])
                    if argv[1] == 'encode':
                        folder = Path(argv[-1]).parent
                        target_list = [json.loads(line) for line in (folder / 'targets.jsonl').read_text().splitlines()]
                        for i, target in enumerate(target_list):
                            cls = target['header']['X-Demo-Class'][0]
                            code = 200 if cls == 'benign' or cls == 'rate-limit' and case in ('rate_refill', 'missing_body', 'blocking_page', 'wrong_identity') else 403 if cls == 'rate-limit' and case == 'rate_403' else 429 if cls == 'rate-limit' else 403
                            error = '' if code == 200 else f'{code} {traffic.responses[code]}'
                            if i == 50 and case == 'network':
                                code, error = 0, 'read timeout'
                            if i == 50 and case == 'business':
                                code, error = 500, '500 Internal Server Error'
                            body = captured_echo(target)
                            if cls == 'rate-limit' and case == 'missing_body':
                                body = None
                            if cls == 'rate-limit' and case == 'blocking_page':
                                body = base64.b64encode(b'Forbidden').decode()
                            if cls == 'rate-limit' and case == 'wrong_identity':
                                echo = json.loads(base64.b64decode(body))
                                echo['headers']['X-Mud-User'] = 'different-synthetic-user'
                                body = base64.b64encode(json.dumps(echo).encode()).decode()
                            kwargs['stdout'].write(json.dumps({'url': target['url'], 'code': code, 'error': error,
                                                             'method': target['method'], 'body': body,
                                                             'timestamp': '2026-10-01T09:22:45Z', 'latency': 5}) + '\n')
                    return subprocess.CompletedProcess(argv, 0)
                with mock.patch.object(traffic.subprocess, 'run', side_effect=tool):
                    self.assertEqual(traffic.run_cycle(value, 'scheduled'), int(case not in ('fresh_rate', 'rate_refill')))
                status = json.loads((root / 'status.json').read_text())
                self.assertEqual(status['count'], 1500)
                self.assertEqual(status['transport_errors'], int(case == 'network'))
                self.assertEqual(status['class_counts'], {'benign': 1350, 'rate-limit': 50, 'waf': 30, 'mud': 30, 'schema': 20, 'endpoint-denial': 20})
                self.assertEqual(len(status['history']), 1)
                self.assertFalse(status['scheduled_pair'])
                self.assertEqual(status['history'][0]['status'], status['status'])
                self.assertEqual(status['security_evidence_scope'], traffic.SECURITY_EVIDENCE_SCOPE)
                if case == 'rate_refill':
                    self.assertEqual(status['benign_success'], 1)
                    self.assertTrue(all(outcome == {'status_counts': {'200': 25}, '429_count': 0, 'rate_denial_observed': False}
                                        for outcome in status['rate_outcomes'].values()))
                    self.assertEqual(traffic.evaluate_summary(status, self.domains), [])
                if case in ('missing_body', 'blocking_page', 'wrong_identity'):
                    self.assertIn('rate_origin_response_unconfirmed', status['failures'])
                    self.assertEqual(status['error_class'], 'metrics_failed')
                if case == 'rate_403':
                    self.assertIn('unexpected_response', status['failures'])
                self.assertTrue((root / 'results' / status['run_id'] / 'accounting.json').exists())


    def test_captured_first_burst_outcome_pattern(self):
        # Reconstruct the captured aggregate pattern, not raw/private timestamps
        # or a live timing proof: run 71f23e7b73354682ad6e8e9a7b68ca13 had
        # 1350 benign 200, 100 expected 403, and 50 rate 200 responses.
        records = [{**r, 'code': 200 if r['class'] in ('benign', 'rate-limit') else 403,
                    'error': '' if r['class'] in ('benign', 'rate-limit') else '403 Forbidden'} for r in self.records]
        report = {**self.report, 'errors': ['403 Forbidden'], 'rate': 50.03279007301814, 'duration': 29_980_338_850}
        self.assertEqual(traffic.evaluate(report, records, self.domains), [])
        for outcome in traffic.rate_outcomes(records, self.domains).values():
            self.assertEqual(outcome, {'status_counts': {'200': 25}, '429_count': 0, 'rate_denial_observed': False})
        accounting = traffic.outcome_accounting(records)
        self.assertEqual(accounting, {'transport_errors': 0, 'http_errors': 100, 'response_failures': 0, 'benign_success': 1})
        for domain in self.domains:
            next(r for r in records if r['domain'] == domain and r['class'] == 'rate-limit').update(code=429, error='429 Too Many Requests')
        report['errors'].append('429 Too Many Requests')
        self.assertEqual(traffic.evaluate(report, records, self.domains), [])
        self.assertEqual(traffic.outcome_accounting(records)['transport_errors'], 0)

    def test_error_outcomes_fail_closed(self):
        for code, error in ((0, ''), (0, '403 Forbidden'), (0, 'connection reset by peer'),
                            (0, 'read timeout'), (403, 'read timeout'), (403, '429 Too Many Requests'),
                            (200, '403 Forbidden')):
            with self.subTest(code=code, error=error):
                records = copy.deepcopy(self.records)
                records[0].update(code=code, error=error)
                report = {**self.report, 'errors': [error] if error else []}
                self.assertIn('transport', traffic.evaluate(report, records, self.domains))
                self.assertEqual(traffic.outcome_accounting(records)['transport_errors'], 1)
        for code in (None, '403', True, -1, 999):
            records = copy.deepcopy(self.records)
            records[0]['code'] = code
            self.assertIn('malformed_metrics', traffic.evaluate(self.report, records, self.domains))
        records = copy.deepcopy(self.records)
        del records[0]['code']
        self.assertIn('malformed_metrics', traffic.evaluate(self.report, records, self.domains))
        for errors in (['unrelated aggregate error'], ['403 Forbidden']):
            self.assertIn('error_accounting', traffic.evaluate({**self.report, 'errors': errors}, self.records, self.domains))
        records = copy.deepcopy(self.records)
        records[0]['error'] = '429 Too Many Requests'
        self.assertIn('error_accounting', traffic.evaluate(self.report, records, self.domains))

    def test_http_business_failure_is_not_transport(self):
        records = copy.deepcopy(self.records)
        next(r for r in records if r['class'] == 'benign').update(code=500, error='500 Internal Server Error')
        report = {**self.report, 'errors': ['500 Internal Server Error']}
        failures = traffic.evaluate(report, records, self.domains)
        self.assertIn('unexpected_response', failures)
        self.assertNotIn('transport', failures)
        self.assertEqual(traffic.outcome_accounting(records)['response_failures'], 1)
        self.assertEqual(traffic.outcome_accounting(records)['transport_errors'], 0)

    def test_valid_benign_schema_and_unique_classes(self):
        for target in self.targets:
            self.assertEqual(target['header']['X-Demo-Run'], ['fresh-run'])
            if target['method'] == 'POST' and target['header']['X-Demo-Class'] == ['benign']:
                self.assertEqual(json.loads(base64.b64decode(target['body'])), {'demo_id': 'fresh-run'})
        self.assertNotEqual(self.targets, traffic.targets(self.domains, 'next-run', 1))
        with self.assertRaises(ValueError):
            traffic.targets(self.domains, 'run', 0, False)

    def test_malformed_metrics(self):
        for field in ('requests', 'duration', 'latencies', 'errors'):
            bad = copy.deepcopy(self.report)
            del bad[field]
            self.assertIn('malformed_metrics', traffic.evaluate(bad, self.records, self.domains))
        for value in ('50', None, float('nan'), float('inf'), True):
            bad = {**self.report, 'rate': value}
            self.assertIn('malformed_metrics', traffic.evaluate(bad, self.records, self.domains))

    def test_missing_domain(self):
        bad = [{**r, 'domain': self.domains[0]} for r in self.records]
        self.assertIn('domains', traffic.evaluate(self.report, bad, self.domains))

    def test_count_and_mix(self):
        bad = [{**r, 'class': 'benign'} for r in self.records]
        self.assertIn('mix', traffic.evaluate(self.report, bad, self.domains))
        self.assertIn('count', traffic.evaluate(self.report, self.records[:-30], self.domains))

    def test_rate_and_duration(self):
        for value in (48.9, 51.1):
            self.assertIn('rate', traffic.evaluate({**self.report, 'rate': value}, self.records, self.domains))
        self.assertIn('duration', traffic.evaluate({**self.report, 'duration': 29_000_000_000}, self.records, self.domains))

    def test_latency_failure(self):
        for key, value in (('99th', 100), ('max', 5_000_000_001), ('mean', 0)):
            bad = copy.deepcopy(self.report)
            bad['latencies'][key] = value
            self.assertIn('latencies', traffic.evaluate(bad, self.records, self.domains))

    def test_transport_and_unexpected_blocks(self):
        bad = copy.deepcopy(self.records)
        bad[0].update(code=0, error='timeout')
        self.assertIn('transport', traffic.evaluate(self.report, bad, self.domains))
        bad = copy.deepcopy(self.records)
        for row in [r for r in bad if r['class'] == 'benign'][:30]:
            row['code'] = 403
        self.assertIn('benign_success', traffic.evaluate(self.report, bad, self.domains))
        bad = [{**r, 'code': 200} if r['class'] != 'benign' else r for r in self.records]
        self.assertIn('expected_denial', traffic.evaluate(self.report, bad, self.domains))

    def test_second_scheduled_failure(self):
        history = [{'trigger': 'scheduled', 'status': 'verified', 'started_epoch': 1000}, {'trigger': 'scheduled', 'status': 'verified', 'started_epoch': 1300}]
        self.assertTrue(traffic.scheduled_pair(history))
        for key, value in (('trigger', 'manual'), ('status', 'failed'), ('started_epoch', 1200)):
            bad = copy.deepcopy(history)
            bad[-1][key] = value
            self.assertFalse(traffic.scheduled_pair(bad))
        self.assertFalse(traffic.scheduled_pair(history[:1]))
        self.assertFalse(traffic.scheduled_pair([{}, {}]))

    def test_missing_authorization_records_failed_run(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), mock.patch.object(traffic, 'cheap_ready') as ready:
            value = {'target_domains': self.domains, 'target_origin_ip': '192.0.2.1', 'mud_bad_traffic': True, 'tool_tier': 'standard'}
            self.assertEqual(traffic.run_cycle(value, 'scheduled'), 1)
            ready.assert_not_called()
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['status'], 'failed')
            self.assertEqual(len(status['history']), 1)
            self.assertFalse(status['scheduled_pair'])
            self.assertEqual(status['attribution_status'], 'pending')

    def test_start_does_not_trigger_manual_burst(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(traffic, 'ROOT', Path(directory)), mock.patch.object(traffic, 'config', return_value={'target_domains': self.domains}), mock.patch.object(traffic, 'cheap_ready') as ready, mock.patch.object(traffic.subprocess, 'run') as run, mock.patch.object(traffic.sys, 'argv', ['tgen-control', 'start']):
            self.assertEqual(traffic.main(), 0)
            ready.assert_called_once()
            run.assert_called_once_with(['systemctl', 'enable', '--now', 'tgen-continuous.timer'], check=True)
            self.assertTrue((Path(directory) / 'authorization.json').exists())

    # Captured read-only from the checksum-pinned owned generator. Format source:
    # https://github.com/tsenart/vegeta/blob/v12.12.0/main.go
    VEGETA_VERSION = (
        'Version: v12.12.0\n'
        'Commit: 03ca49e9b419c106db29d687827c4c823d8b8ece\n'
        'Runtime: go1.22.5 linux/amd64\n'
        'Date: 2024-07-29T17:35:40Z+0000\n'
    )

    def test_pinned_vegeta_capture_checks_origin_and_both_domains(self):
        value = {'target_domains': self.domains, 'target_origin_ip': '192.0.2.1', 'tool_tier': 'standard', 'mud_bad_traffic': True}
        with mock.patch.object(traffic.subprocess, 'run', return_value=subprocess.CompletedProcess(
                ['vegeta', '-version'], 0, stdout=self.VEGETA_VERSION)) as run, \
                mock.patch.object(traffic.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value.__enter__.return_value.status = 200
            traffic.cheap_ready(value)
            run.assert_called_once_with(['vegeta', '-version'], capture_output=True, text=True, check=True)
            self.assertEqual(build.return_value.open.call_args_list, [
                mock.call(f'http://{host}/health', timeout=5)
                for host in [value['target_origin_ip'], *self.domains]
            ])

    def test_wrong_vegeta_version_blocks_readiness_without_network(self):
        invalid = [
            '',
            self.VEGETA_VERSION.replace('v12.12.0', 'v12.12.1'),
            self.VEGETA_VERSION.replace('v12.12.0', '12.12.0'),
            self.VEGETA_VERSION.replace('v12.12.0', 'v12.12.0-garbage'),
            self.VEGETA_VERSION.replace('Version:', 'Version :'),
            self.VEGETA_VERSION.replace('Version: v12.12.0\n', 'Version: v12.12.0 garbage\n'),
            self.VEGETA_VERSION + 'unexpected garbage\n',
            self.VEGETA_VERSION.replace('Commit:', 'Unknown:'),
        ]
        for output in invalid:
            with self.subTest(output=output), mock.patch.object(traffic.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(['vegeta', '-version'], 0, stdout=output)), \
                    mock.patch.object(traffic.urllib.request, 'build_opener') as build:
                with self.assertRaisesRegex(ValueError, 'mandatory pinned'):
                    traffic.cheap_ready({'target_domains': self.domains, 'target_origin_ip': '192.0.2.1', 'tool_tier': 'standard', 'mud_bad_traffic': True})
                build.assert_not_called()

    def test_failed_or_missing_vegeta_blocks_readiness_without_network(self):
        for failure in (FileNotFoundError('vegeta'), subprocess.CalledProcessError(
                1, ['vegeta', '-version'], output=self.VEGETA_VERSION)):
            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(traffic.subprocess, 'run', side_effect=failure) as run, \
                    mock.patch.object(traffic.urllib.request, 'build_opener') as build:
                with self.assertRaises(type(failure)):
                    traffic.cheap_ready({'target_domains': self.domains, 'target_origin_ip': '192.0.2.1', 'tool_tier': 'standard', 'mud_bad_traffic': True})
                run.assert_called_once_with(['vegeta', '-version'], capture_output=True, text=True, check=True)
                build.assert_not_called()

    def test_real_missing_vegeta_fails_before_network(self):
        with tempfile.TemporaryDirectory() as empty_path, \
                mock.patch.dict(traffic.os.environ, {'PATH': empty_path}), \
                mock.patch.object(traffic.urllib.request, 'build_opener') as build:
            with self.assertRaises(FileNotFoundError):
                traffic.cheap_ready({'target_domains': self.domains, 'target_origin_ip': '192.0.2.1', 'tool_tier': 'standard', 'mud_bad_traffic': True})
            build.assert_not_called()


    def test_embedded_shell_syntax_and_wire_limit(self):
        # YAML parser is development-only; guest runtime uses Python stdlib.
        template, data = rendered_cloud_config(self.domains)
        self.assertLess(len(template.encode()), 65536)
        embedded = next(f['content'] for f in data['write_files'] if f['path'] == '/usr/local/lib/demo_traffic.py')
        canonical = (Path(__file__).resolve().parents[1] / 'scripts/demo_traffic.py').read_text()
        self.assertEqual(embedded.strip(), canonical.strip())
        compile(embedded, 'embedded-demo-traffic', 'exec')
        checked = 0
        for item in data['write_files']:
            content = item.get('content', '')
            if content.startswith(('#!/bin/bash', '#!/bin/sh')):
                subprocess.run(['bash', '-n'], input=content, text=True, check=True)
                checked += 1
        for command in data['runcmd']:
            if isinstance(command, str):
                subprocess.run(['bash', '-n'], input=command, text=True, check=True)
                checked += 1
        self.assertGreater(checked, 10)
        print(f'Generator rendered custom-data: {len(template.encode())} bytes; bash -n scripts: {checked}')
        timer = next(f['content'] for f in data['write_files'] if f['path'].endswith('.timer'))
        self.assertIn('OnActiveSec=300s', timer)
        self.assertIn('OnUnitActiveSec=300s', timer)
        self.assertNotIn('OnBootSec', timer)
        self.assertNotIn('enable --now tgen-continuous.timer', template)

    def test_rendered_boot_phase_leaves_traffic_stopped(self):
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'disable --now tgen-continuous.timer' in item)
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / 'status.json'
            calls = Path(directory) / 'systemctl.calls'
            source = 'systemctl() { printf "%s\\n" "$*" >> "$CALLS"; };\n' + phase
            source = source.replace('/opt/traffic-generator/status.json', str(status))
            import os
            subprocess.run(['sh', '-c', source], check=True, text=True,
                           env=dict(os.environ, CALLS=str(calls)))
            self.assertEqual(json.loads(status.read_text())['status'], 'stopped')
            self.assertEqual(calls.read_text().splitlines(), [
                'daemon-reload', 'disable --now tgen-continuous.timer',
                'stop tgen-continuous.service'])


    def test_required_installation_failure_stops_cloudinit(self):
        import shlex
        _, data = rendered_cloud_config(self.domains)
        # Match cloud-init's shellify: each scalar remains in the same /bin/sh script.
        source = '\n'.join(item if isinstance(item, str) else shlex.join(item)
                           for item in data['runcmd'])
        result = subprocess.run(['sh', '-c', 'sysctl() { return 17; };\n' + source],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 17)
        self.assertIn('provisioning failed (17)', result.stderr)
        self.assertNotIn('traffic-generator provisioned', result.stdout)

    def test_security_install_failure_cannot_be_masked_by_completion(self):
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing security binaries' in item)
        phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
        stubs = '''
        log_phase() { :; }
        dpkg() { echo amd64; }
        ghlatest() { echo 1.2.3; }
        fetch_url() { echo "fetch:$1"; }
        unzip() { return 18; }
        '''
        result = subprocess.run(['sh', '-c', data['runcmd'][0] + stubs + phase],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 18)
        self.assertNotIn('Phase 3 complete', result.stdout)

    def test_go_install_children_inherit_clean_cloudinit_environment(self):
        import hashlib
        import io
        import shlex
        import tarfile
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing load testing tools' in item)
        phase = phase[:phase.index('echo "Installing checksum-pinned Vegeta')]
        phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
        helpers = next(item['content'] for item in data['write_files']
                       if item['path'] == '/usr/local/lib/cloud-init-helpers.sh')
        digest = 'd0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b'
        self.assertIn('https://go.dev/dl/go1.26.8.linux-amd64.tar.gz', phase)
        self.assertIn(digest, phase)
        self.assertIn('export GOTOOLCHAIN=local', data['runcmd'][0])
        self.assertNotIn('@latest', phase)
        self.assertNotIn('golang-go', phase)
        # A real child executable checks inherited variables, not shell-local assignments.
        probe = b'''#!/bin/sh
set -eu
[ "${HOME:-}" = "$EXPECTED_HOME" ] || exit 31
[ "${XDG_CACHE_HOME:-}" = "$HOME/.cache" ] || exit 32
[ "${GOCACHE:-}" = "$HOME/.cache/go-build" ] || exit 33
[ "${GOPATH:-}" = "$EXPECTED_GOPATH" ] || exit 34
[ "${GOMODCACHE:-}" = "$GOPATH/pkg/mod" ] || exit 35
[ "${GOTOOLCHAIN:-}" = local ] || exit 36
for directory in "$GOCACHE" "$GOPATH" "$GOMODCACHE"; do
    [ -d "$directory" ] && [ -w "$directory" ] || exit 37
done
if [ "$1" = version ]; then
    printf 'go version %s linux/amd64\\n' "${PROBE_VERSION:-go1.26.8}"
    exit 0
fi
printf '%s\\n' "$*" >> "$CALLS"
[ "$2" != "${FAIL_PACKAGE:-}" ] || exit 41
case "$2" in
github.com/rakyll/hey@v0.1.5) touch "$GOPATH/bin/hey" ;;
github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9)
    touch "$GOPATH/bin/gotestwaf"
    mkdir -p "$GOMODCACHE/github.com/wallarm/gotestwaf@v0.5.9/testcases"
    touch "$GOMODCACHE/github.com/wallarm/gotestwaf@v0.5.9/config.yaml" ;;
*) exit 42 ;;
esac
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'go-fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                entry = tarfile.TarInfo('go/bin/go')
                entry.mode = 0o755
                entry.size = len(probe)
                output.addfile(entry, io.BytesIO(probe))
            fixture_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / 'bin').mkdir()
            initialization = data['runcmd'][0].replace('/root', str(root / 'home'))
            initialization = initialization.replace('/opt/go', str(root / 'gopath'))
            installer = phase.replace('/opt/traffic-generator-toolchain', str(root / 'toolchain'))
            installer = installer.replace('/opt/gotestwaf', str(root / 'gotestwaf'))
            installer = installer.replace('/opt/go', str(root / 'gopath'))
            installer = installer.replace('/usr/local/bin', str(root / 'bin'))
            installer = installer.replace('/tmp/go.tar.gz', str(root / 'download.tar.gz'))
            stubs = (helpers + '\ndpkg() { echo amd64; };\n'
                     'log_phase() { :; }; sleep() { :; }; chown() { :; };\n'
                     'fetch_url() { printf "fetch:%s\\n" "$1"; cp '
                     + shlex.quote(str(archive)) + ' "$2"; };\n')
            environment = {'PATH': '/usr/bin:/bin', 'EXPECTED_HOME': str(root / 'home'),
                           'EXPECTED_GOPATH': str(root / 'gopath'), 'CALLS': str(root / 'calls')}
            source = initialization + stubs + installer
            # Reproduce missing HOME without the common exported setup.
            missing = subprocess.run(['sh', '-c', stubs + installer.replace(digest, fixture_digest)],
                                     env=environment, text=True, capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('XDG_CACHE_HOME', missing.stderr)
            bad_hash = subprocess.run(['sh', '-c', source], env=environment,
                                      text=True, capture_output=True)
            self.assertNotEqual(bad_hash.returncode, 0)
            self.assertIn('FAILED', bad_hash.stdout)
            self.assertFalse((root / 'toolchain/go/bin/go').exists())
            source = source.replace(digest, fixture_digest)
            good = subprocess.run(['sh', '-c', source], env=environment, text=True, capture_output=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual((root / 'calls').read_text().splitlines(), [
                'install github.com/rakyll/hey@v0.1.5',
                'install github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9'])
            self.assertEqual((root / 'gopath').stat().st_mode & 0o777, 0o700)
            missing_home = subprocess.run(
                ['sh', '-c', shlex.quote(str(root / 'toolchain/go/bin/go'))
                 + ' install github.com/rakyll/hey@v0.1.5'],
                env=environment, text=True, capture_output=True)
            self.assertEqual(missing_home.returncode, 31)
            for package in ('github.com/rakyll/hey@v0.1.5',
                            'github.com/wallarm/gotestwaf/cmd/gotestwaf@v0.5.9'):
                failed = subprocess.run(['sh', '-c', source],
                                        env=dict(environment, FAIL_PACKAGE=package),
                                        text=True, capture_output=True)
                self.assertEqual(failed.returncode, 1, failed.stderr)
                self.assertIn('provisioning failed (1)', failed.stderr)
                self.assertEqual((root / 'calls').read_text().splitlines()[-3:],
                                 ['install ' + package] * 3)
            wrong_version = subprocess.run(['sh', '-c', source],
                                           env=dict(environment, PROBE_VERSION='go1.22.0'),
                                           text=True, capture_output=True)
            self.assertNotEqual(wrong_version.returncode, 0)
            self.assertIn('Unexpected Go version', wrong_version.stderr)

    def test_versioned_downloads_expand_in_parent_shell(self):
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing security binaries' in item)
        source = phase[phase.index('echo "Installing ffuf'):phase.index('echo "Installing feroxbuster')]
        stubs = '''
        set -eu
        DPKG_ARCH=amd64
        ghlatest() { echo 1.2.3; }
        uname() { echo x86_64; }
        fetch_url() { echo "fetch:$1"; }
        tar() { :; }
        '''
        result = subprocess.run(['sh', '-c', stubs + source], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/v1.2.3/ffuf_1.2.3_linux_amd64.tar.gz', result.stdout)
        self.assertIn('/v1.2.3/gobuster_Linux_x86_64.tar.gz', result.stdout)

    def test_dalfox_pinned_archive_layout_and_fail_closed_install(self):
        import hashlib
        import io
        import shlex
        import tarfile
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing security binaries' in item)
        source = phase[phase.index('echo "Installing dalfox'):phase.index('echo "Installing amass')]
        digest = '3b059b6bb55e686b5f240852ea6a6750aa5e35a3b404e4027ffe505e2b60a470'
        self.assertIn('DALFOX_VER=3.2.3', source)
        self.assertIn(digest, source)
        self.assertNotIn('ghlatest', source)
        self.assertNotIn('dalfox-linux-', source)
        # Exact member observed in official asset 566035019, independently hash-verified.
        member = 'dalfox-v3.2.3-linux-x86_64/dalfox'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'fixture.tar.gz'
            binary = b'#!/bin/sh\nprintf "dalfox 3.2.3\\n"\n'
            with tarfile.open(archive, 'w:gz') as output:
                entry = tarfile.TarInfo(member)
                entry.mode = 0o755
                entry.size = len(binary)
                output.addfile(entry, io.BytesIO(binary))
            fixture_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / 'bin').mkdir()
            installer = source.replace('/tmp/dalfox.tar.gz', str(root / 'download.tar.gz'))
            installer = installer.replace('/usr/local/bin', str(root / 'bin'))
            stubs = ('set -eu\nDPKG_ARCH=amd64\n'
                     'fetch_url() { printf "fetch:%s\\n" "$1"; cp '
                     + shlex.quote(str(archive)) + ' "$2"; };\n')
            # A wrong hash must fail before tar is invoked or any binary is installed.
            bad = subprocess.run(['sh', '-c', stubs + installer], text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('FAILED', bad.stdout)
            self.assertFalse((root / 'bin/dalfox').exists())
            good = subprocess.run(['sh', '-c', stubs + installer.replace(digest, fixture_digest)],
                                  text=True, capture_output=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn('/v3.2.3/dalfox-v3.2.3-linux-x86_64.tar.gz', good.stdout)
            self.assertEqual((root / 'bin/dalfox').read_bytes(), binary)
            self.assertFalse((root / 'download.tar.gz').exists())
            failed_fetch = subprocess.run(['sh', '-c', stubs + 'fetch_url() { return 23; };\n'
                                           + installer], text=True, capture_output=True)
            self.assertEqual(failed_fetch.returncode, 23)
            unsupported = subprocess.run(['sh', '-c', stubs + 'DPKG_ARCH=arm64\n' + installer],
                                         text=True, capture_output=True)
            self.assertNotEqual(unsupported.returncode, 0)
            self.assertNotIn('fetch:', unsupported.stdout)

    def test_zap_is_full_tier_pinned_and_checksum_failure_is_fatal(self):
        stubs = '''
        log_phase() { :; }
        install_packages() { :; }
        fetch_url() { echo "fetch:$1"; }
        tar() { echo extracted; }
        mv() { :; }
        chmod() { :; }
        timeout() { echo "timeout:$*"; }
        '''
        for tier in ('standard', 'full'):
            _, data = rendered_cloud_config(self.domains, tier)
            phase = next(item for item in data['runcmd']
                         if isinstance(item, str) and 'installing configured full-tier tools' in item)
            phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
            for checksum_status in (0, 19):
                with self.subTest(tier=tier, checksum_status=checksum_status), tempfile.TemporaryDirectory() as directory:
                    source = phase.replace('/usr/local/bin/zap', str(Path(directory) / 'zap'))
                    checker = 'sha256sum() { cat; return ' + str(checksum_status) + '; };\n'
                    result = subprocess.run(['sh', '-c', data['runcmd'][0] + stubs + checker + source],
                                            text=True, capture_output=True)
                    expected = checksum_status if tier == 'full' else 0
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if tier == 'standard':
                        self.assertNotIn('fetch:', result.stdout)
                    else:
                        self.assertIn('/v2.17.0/ZAP_2.17.0_Linux.tar.gz', result.stdout)
                        self.assertIn('efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a', result.stdout)
                        self.assertEqual('extracted' in result.stdout, checksum_status == 0)
                        self.assertEqual('timeout:60 zap -version' in result.stdout, checksum_status == 0)

    def test_real_checksum_rejects_corrupted_zap_before_extracting(self):
        _, data = rendered_cloud_config(self.domains, 'full')
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing configured full-tier tools' in item)
        phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
        stubs = '''
        log_phase() { :; }
        install_packages() { :; }
        fetch_url() { printf corrupted > "$2"; }
        tar() { echo MUST_NOT_EXTRACT; return 90; }
        '''
        with tempfile.TemporaryDirectory() as directory:
            phase = phase.replace('/tmp/zap.tar.gz', str(Path(directory) / 'zap.tar.gz'))
            phase = phase.replace('/usr/local/bin/zap', str(Path(directory) / 'zap'))
            result = subprocess.run(['sh', '-c', data['runcmd'][0] + stubs + phase],
                                    text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAILED', result.stdout)
        self.assertNotIn('MUST_NOT_EXTRACT', result.stdout)


    def test_standard_smoke_does_not_require_full_tier_tools(self):
        stubs = '''
        set -eu
        log_phase() { :; }
        command() {
          case "$2" in zap|msfconsole|java) return 1 ;; *) return 0 ;; esac
        }
        '''
        for tier in ('standard', 'full'):
            _, data = rendered_cloud_config(self.domains, tier)
            smoke = next(item for item in data['runcmd']
                         if isinstance(item, str) and 'running smoke test' in item)
            smoke = smoke.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
            with self.subTest(tier=tier), tempfile.TemporaryDirectory() as directory:
                smoke = smoke.replace('/opt/traffic-generator/status.json', str(Path(directory) / 'status.json'))
                result = subprocess.run(['sh', '-c', stubs + smoke], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0 if tier == 'standard' else 1, result.stderr)
                status = json.loads((Path(directory) / 'status.json').read_text())
                self.assertEqual(status['tools_fail'], 0 if tier == 'standard' else 3)

    def test_python_tool_install_is_hash_locked_and_never_global(self):
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing isolated Python' in item)
        self.assertIn('/usr/bin/python3 -m venv /opt/traffic-generator/venv', phase)
        self.assertIn('sys.prefix != sys.base_prefix', phase)
        self.assertIn('timeout 900 /opt/traffic-generator/venv/bin/python -m pip --isolated install', phase)
        self.assertIn('--require-hashes', phase)
        self.assertNotIn('--system-site-packages', phase)
        for flag in ('--break-system-packages', '--ignore-installed'):
            self.assertNotIn(flag, phase)
        lock = next(f['content'] for f in data['write_files'] if f['path'].endswith('python-tools.lock'))
        lines = lock.strip().splitlines()
        self.assertGreater(len(lines), 80)
        for line in lines:
            self.assertRegex(line, r'^\S+==\S+ --hash=sha256:[a-f0-9]{64}$')
        for pin in ('pip==26.2.1', 'blinker==1.9.0', 'Flask==3.1.3', 'mitmproxy==12.2.3'):
            self.assertTrue(any(line.startswith(pin + ' ') for line in lines))
        for removed in ('wfuzz', 'pycurl', 'chardet', 'setuptools'):
            self.assertFalse(any(line.lower().startswith(removed + '==') for line in lines))
        self.assertNotIn('wfuzz', phase)
        smoke = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'running smoke test' in item)
        self.assertNotIn('wfuzz', smoke)
        self.assertIn(' ffuf ', smoke)

    def test_real_venv_hides_distro_blinker_without_network(self):
        # Real interpreter and pip, no mocked isolation and no package-index access.
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            venv = root / 'venv'
            subprocess.run(['/usr/bin/python3', '-m', 'venv', str(venv)], check=True, timeout=60)
            python = str(venv / 'bin/python')
            check = 'import sys, importlib.util; assert sys.prefix != sys.base_prefix; assert importlib.util.find_spec("blinker") is None'
            subprocess.run([python, '-I', '-c', check], check=True, timeout=30)
            # Minimal offline wheel fixture exercises pip's actual install boundary.
            wheel = root / 'blinker-1.9.0-py3-none-any.whl'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('blinker/__init__.py', '__version__ = "1.9.0"\n')
                archive.writestr('blinker-1.9.0.dist-info/METADATA',
                                 'Metadata-Version: 2.1\nName: blinker\nVersion: 1.9.0\n')
                archive.writestr('blinker-1.9.0.dist-info/WHEEL',
                                 'Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
                archive.writestr('blinker-1.9.0.dist-info/RECORD', '')
            result = subprocess.run([python, '-m', 'pip', '--isolated', 'install', '--no-index',
                                     '--no-deps', str(wheel)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('Uninstalling', result.stdout)
            subprocess.run([python, '-I', '-c', 'import blinker, sys; assert blinker.__file__.startswith(sys.prefix)'],
                           check=True, timeout=30)

    def test_python_phase_failure_stops_provisioning(self):
        _, data = rendered_cloud_config(self.domains)
        phase = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'installing isolated Python' in item)
        phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
        for failure in ('install', 'startup'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                source = phase.replace('/opt/traffic-generator', directory)
                stubs = 'set -eu\nlog_phase() { :; }\n'
                if failure == 'install':
                    stubs += 'retry_cmd() { return 31; }\n'
                    expected = 31
                else:
                    stubs += 'retry_cmd() { :; }\ntimeout() { return 43; }\n'
                    expected = 43
                result = subprocess.run(['sh', '-c', stubs + source + '\necho unexpected-completion'],
                                        text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertNotIn('unexpected-completion', result.stdout)

    def test_python_tools_share_canonical_path_and_missing_mitmdump_blocks_ready(self):
        _, data = rendered_cloud_config(self.domains)
        files = {f['path']: f['content'] for f in data['write_files']}
        path = '/opt/traffic-generator/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        for name in ('/etc/environment', '/etc/profile.d/traffic-generator.sh',
                     '/usr/local/bin/tgen-control', '/etc/systemd/system/tgen-continuous.service'):
            self.assertIn(path, files[name])
        self.assertIn('exec /usr/bin/python3', files['/usr/local/bin/tgen-control'])
        self.assertIn('exec sudo -n /usr/local/bin/tgen-control', files['/usr/local/bin/tgen-control'])
        smoke = next(item for item in data['runcmd']
                     if isinstance(item, str) and 'running smoke test' in item)
        smoke = smoke.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
        self.assertIn(path, smoke)
        stubs = 'set -eu\nlog_phase() { :; }\ncommand() { [ "$2" != mitmdump ]; }\n'
        with tempfile.TemporaryDirectory() as directory:
            smoke = smoke.replace('/opt/traffic-generator/status.json', str(Path(directory) / 'status.json'))
            result = subprocess.run(['sh', '-c', stubs + smoke], text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('MISSING: mitmdump', result.stdout)
            status = json.loads((Path(directory) / 'status.json').read_text())
            self.assertEqual(status['status'], 'degraded')
            self.assertEqual(status['tools_fail'], 1)

    @unittest.skipUnless(__import__('os').environ.get('VALIDATE_PYTHON_TOOL_LOCK') == '1',
                         'Explicit network dependency validation only')
    def test_published_python_lock_installs_on_ubuntu_python312(self):
        # This verifies the real locked packages locally, not guest/live acceptance.
        import shutil
        _, data = rendered_cloud_config(self.domains)
        lock = next(f['content'] for f in data['write_files'] if f['path'].endswith('python-tools.lock'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            venv = root / 'venv'
            subprocess.run(['/usr/bin/python3', '-m', 'venv', str(venv)], check=True, timeout=60)
            python = str(venv / 'bin/python')
            requirements = root / 'python-tools.lock'
            requirements.write_text(lock)
            argv = [python, '-m', 'pip', '--isolated', 'install', '--require-hashes', '-r', str(requirements)]
            subprocess.run(argv + ['--dry-run'], check=True, timeout=900)
            phase = next(item for item in data['runcmd']
                         if isinstance(item, str) and 'installing isolated Python' in item)
            phase = phase.replace('. /usr/local/lib/cloud-init-helpers.sh', '')
            phase = phase.replace('/opt/traffic-generator', str(root))
            helpers = 'set -eu\nlog_phase() { :; }\nretry_cmd() { shift 2; "$@"; }\n'
            subprocess.run(['sh', '-c', helpers + phase], check=True, timeout=1100)
            for tool in ('scapy', 'arjun', 'hashid', 'pwn', 'mitmproxy', 'mitmdump', 'mitmweb', 'sslyze', 'smbclient.py'):
                self.assertEqual(shutil.which(tool, path=str(venv / 'bin')), str(venv / 'bin' / tool))
                flag = '--version' if tool in ('mitmproxy', 'mitmdump', 'mitmweb') else '-h'
                subprocess.run([str(venv / 'bin' / tool), flag], check=True, timeout=30,
                               stdout=subprocess.DEVNULL)
            subprocess.run([python, '-I', '-c',
                            'import blinker, sys, importlib.util; '
                            'assert blinker.__file__.startswith(sys.prefix); '
                            'assert importlib.util.find_spec("wfuzz") is None'], check=True, timeout=30)



if __name__ == '__main__':
    unittest.main()
