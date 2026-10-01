#!/usr/bin/env python3
"""Bounded showcase runner. Response checks are NOT attributed security proof."""
import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
from http.client import responses
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path('/opt/traffic-generator')
CLASSES = ('waf', 'schema', 'endpoint-denial', 'rate-limit', 'mud')
ATTACK_ROTATION = ('waf', 'schema', 'endpoint-denial', 'rate-limit', 'mud', 'waf', 'schema', 'rate-limit', 'mud', 'endpoint-denial', 'waf', 'rate-limit', 'mud', 'rate-limit', 'rate-limit')
SECURITY_EVIDENCE_SCOPE = 'measurement only; fresh control attribution required'


def metric_failures(count, rate, duration, latencies):
    """Validate measured metrics in seconds and nanoseconds, shared by consumers."""
    failures = []
    numbers = [count, rate, duration] + [latencies[k] for k in ('min', 'mean', '50th', '90th', '95th', '99th', 'max')]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in numbers):
        raise ValueError('non-finite or negative metric')
    if not 1485 <= count <= 1515:
        failures.append('count')
    if not 49 <= rate <= 51:
        failures.append('rate')
    if not 29.5 <= duration <= 30.5:
        failures.append('duration')
    if not latencies['min'] <= latencies['50th'] <= latencies['90th'] <= latencies['95th'] <= latencies['99th'] <= latencies['max'] or not latencies['min'] <= latencies['mean'] <= latencies['max']:
        failures.append('latencies')
    if latencies['max'] > 5_000_000_000 or latencies['mean'] <= 0:
        failures.append('latencies')
    return failures


def evaluate_summary(summary, domains):
    """Validate the actual guest summary; never manufacture per-request records."""
    failures = []
    try:
        failures.extend(metric_failures(summary['count'], summary['rate'], summary['duration_seconds'], summary['latencies']))
        counts = summary['class_counts']
        values = list(counts.values()) + [summary['transport_errors'], summary['benign_success']]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in values):
            raise ValueError('invalid accounting')
        if set(counts) != {'benign', *CLASSES} or any(not isinstance(v, int) or v <= 0 for v in counts.values()) or sum(counts.values()) != summary['count']:
            failures.append('classes')
        if not .89 <= counts['benign'] / summary['count'] <= .91:
            failures.append('mix')
        if not .99 <= summary['benign_success'] <= 1:
            failures.append('benign_success')
        if summary['transport_errors'] != 0:
            failures.append('transport')
        if set(summary['domains']) != set(domains) or len(set(domains)) < 2:
            failures.append('domains')
        if summary['security_evidence_scope'] != SECURITY_EVIDENCE_SCOPE:
            failures.append('evidence_scope')
        outcomes = summary['rate_outcomes']
        if set(outcomes) != set(domains):
            failures.append('rate_outcomes')
        total = 0
        for outcome in outcomes.values():
            statuses = outcome['status_counts']
            if not statuses or not set(statuses) <= {'200', '429'} or any(type(v) is not int or v < 0 for v in statuses.values()):
                raise ValueError('invalid rate outcomes')
            denied = statuses.get('429', 0)
            if type(outcome['429_count']) is not int or outcome['429_count'] != denied or type(outcome['rate_denial_observed']) is not bool or outcome['rate_denial_observed'] != (denied > 0):
                failures.append('rate_outcomes')
            total += sum(statuses.values())
        if total != counts['rate-limit']:
            failures.append('rate_outcomes')
        if summary['status'] != 'verified' or summary['failures'] != []:
            failures.append('guest_evaluation')
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        failures.append('malformed_metrics')
    return sorted(set(failures))


def transport_error(record):
    """Vegeta v12.12.0 sets Error=r.Status for completed non-success HTTP.

    attack.go assigns Code only after reading the complete response body; code
    zero therefore remains a transport failure even with an HTTP-looking error.
    """
    code, error = record['code'], record['error']
    if isinstance(code, bool) or not isinstance(code, int) or (code != 0 and code not in responses) or not isinstance(error, str):
        raise ValueError('malformed response outcome')
    if code == 0:
        return True
    return bool(error) and (200 <= code < 400 or error != f'{code} {responses[code]}')


def response_failure(record):
    code, cls = record['code'], record['class']
    return (cls == 'benign' and not 200 <= code < 300 or
            cls in ('waf', 'schema', 'endpoint-denial') and code not in (400, 403) or
            cls == 'rate-limit' and code not in (200, 429) or
            cls == 'mud' and code not in (200, 400, 403, 429))


def outcome_accounting(records):
    transport = [transport_error(r) for r in records]
    benign = [r for r in records if r['class'] == 'benign']
    return {'transport_errors': sum(transport),
            'http_errors': sum(bool(r['error']) and not failed for r, failed in zip(records, transport)),
            'response_failures': sum(response_failure(r) for r in records),
            'benign_success': sum(200 <= r['code'] < 300 and not transport_error(r) for r in benign) / max(1, len(benign))}


def rate_origin_response(record):
    """Confirm actual Vegeta base64 body echoes the fresh rate request at httpbin.

    Owned capture 1138b519: nginx strips /httpbin; anything returns method,
    url, and headers (including Host and X-Mud-User). Status alone is insufficient.
    """
    try:
        request = urllib.parse.urlsplit(record['url'])
        query = urllib.parse.parse_qs(request.query)
        run = query['demo_run'][0]
        body = json.loads(base64.b64decode(record['body'], validate=True))
        headers = {k.lower(): v for k, v in body['headers'].items()}
        echoed = urllib.parse.urlsplit(body['url'])
        return (record['method'] == body['method'] == 'GET'
                and request.hostname == record['domain'] == echoed.hostname
                and request.path == '/httpbin/anything/rate-limit'
                and echoed.path == '/anything/rate-limit'
                and echoed.scheme == request.scheme == 'http'
                and urllib.parse.parse_qs(echoed.query) == query
                and query['demo_class'] == ['rate-limit']
                and query['demo_run'] == [run]
                and headers['host'] == record['domain']
                and headers['x-mud-user'] == 'rate-limit-' + run)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return False


def rate_outcomes(records, domains):
    outcomes = {}
    for domain in domains:
        rows = [r for r in records if r['domain'] == domain and r['class'] == 'rate-limit']
        counts = {str(code): sum(r['code'] == code for r in rows) for code in sorted({r['code'] for r in rows})}
        denied = counts.get('429', 0)
        outcomes[domain] = {'status_counts': counts, '429_count': denied, 'rate_denial_observed': denied > 0}
    return outcomes


def evaluate(report, records, domains):
    """Fail closed on malformed metrics and measured contract violations."""
    failures = []
    try:
        count = report['requests']
        rate = report['rate']
        duration = report['duration'] / 1e9
        latencies = report['latencies']
        failures.extend(metric_failures(count, rate, duration, latencies))
        if count != len(records):
            failures.append('count')
        observed = {r['domain'] for r in records}
        if observed != set(domains) or len(observed) < 2:
            failures.append('domains')
        benign = [r for r in records if r['class'] == 'benign']
        if not records or not .89 <= len(benign) / len(records) <= .91:
            failures.append('mix')
        accounting = outcome_accounting(records)
        if not benign or accounting['benign_success'] < .99:
            failures.append('benign_success')
        if accounting['transport_errors']:
            failures.append('transport')
        errors = report['errors']
        if not isinstance(errors, list) or any(not isinstance(e, str) or not e for e in errors):
            raise ValueError('malformed aggregate errors')
        if set(errors) != {r['error'] for r in records if r['error']}:
            failures.append('error_accounting')
        if any(r['class'] == 'benign' and response_failure(r) for r in records):
            failures.append('unexpected_response')
        if set(r['class'] for r in records) != {'benign', *CLASSES}:
            failures.append('classes')
        if any(r['class'] in ('waf', 'schema', 'endpoint-denial') and r['code'] not in (400, 403) for r in records):
            failures.append('expected_denial')
        if any(r['class'] == 'rate-limit' and r['code'] not in (200, 429) or r['class'] == 'mud' and r['code'] not in (200, 400, 403, 429) for r in records):
            failures.append('unexpected_response')
        if any(r['class'] == 'rate-limit' and r['code'] == 200 and not rate_origin_response(r) for r in records):
            failures.append('rate_origin_response_unconfirmed')
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        failures.append('malformed_metrics')
    return sorted(set(failures))


def scheduled_pair(history):
    """Only two consecutive successful scheduled cycles satisfy cadence evidence."""
    try:
        return len(history) >= 2 and all(x.get('trigger') == 'scheduled' and x.get('status') == 'verified' for x in history[-2:]) and 295 <= history[-1]['started_epoch'] - history[-2]['started_epoch'] <= 310
    except (KeyError, TypeError, ValueError):
        return False


def targets(domains, run, sequence, mud=True):
    result = []
    # Preserve the global 90/10 budget, not a per-second attack ratio.
    # Move existing rate probes to the first 50 slots (0.98s at 50/s), with
    # alternating hosts and one fresh rate identity; never add requests.
    for i in range(1500):
        attack_index = (i // 20) * 2 + (i % 20 // 10)
        cls = ATTACK_ROTATION[(attack_index + sequence) % len(ATTACK_ROTATION)] if i % 10 == 9 else 'benign'
        domain = domains[(i + i // 10) % len(domains)]
        method, path, body = 'GET', '/httpbin/get', None
        if cls == 'benign' and i % 4 == 0:
            method, path, body = 'POST', '/httpbin/post', {'demo_id': run}
        elif cls in ('waf', 'mud'):
            path = '/httpbin/get?q=%27%20OR%201%3D1--'
        elif cls == 'schema':
            method, path, body = 'POST', '/httpbin/post', {}
        elif cls == 'endpoint-denial':
            method, path = ('POST' if attack_index % 2 else 'DELETE'), '/httpbin/anything/admin'
        elif cls == 'rate-limit':
            path = '/httpbin/anything/rate-limit'
        identity = f'{cls}-{run}' if cls in ('rate-limit', 'mud') else f'{cls}-{run}-{i}'
        if cls == 'mud' and not mud:
            raise ValueError('showcase requires mud_bad_traffic')
        url = f'http://{domain}{path}'
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode({'demo_run': run, 'demo_class': cls})
        headers = {'X-MUD-User': [identity], 'X-Demo-Class': [cls], 'X-Demo-Run': [run]}
        target = {'method': method, 'url': url, 'header': headers}
        if body is not None:
            headers['Content-Type'] = ['application/json']
            target['body'] = base64.b64encode(json.dumps(body).encode()).decode()
        result.append(target)
    rate = [t for t in result if t['header']['X-Demo-Class'] == ['rate-limit']]
    by_domain = [[t for t in rate if urllib.parse.urlsplit(t['url']).hostname == domain] for domain in domains]
    return [t for pair in zip(*by_domain) for t in pair] + [t for t in result if t['header']['X-Demo-Class'] != ['rate-limit']]


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(tmp, path)


class ConfigurationError(ValueError):
    """Safe configuration reason; never includes input values or response bodies."""


def validate_config(value):
    try:
        if not isinstance(value, dict) or set(value) != {'target_domains', 'target_origin_ip', 'tool_tier', 'mud_bad_traffic'}:
            raise ConfigurationError('invalid_configuration')
        domains = value['target_domains']
        if not isinstance(domains, list) or len(domains) != 2 or any(not isinstance(d, str) or len(d) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in d.split('.')) for d in domains) or len(set(domains)) != 2:
            raise ConfigurationError('invalid_domains')
        origin = ipaddress.ip_address(value['target_origin_ip'])
        if origin.version != 4 or origin.is_loopback or origin.is_unspecified or origin.is_multicast:
            raise ConfigurationError('invalid_origin')
        if value['tool_tier'] not in ('standard', 'full'):
            raise ConfigurationError('invalid_tool_tier')
        if value['mud_bad_traffic'] is not True:
            raise ConfigurationError('mud_bad_traffic_required')
        # Exercise the same complete target generator used by the scheduled attack.
        targets(domains, 'configuration-check', 0, value['mud_bad_traffic'])
    except ConfigurationError:
        raise
    except (KeyError, TypeError, ValueError):
        raise ConfigurationError('invalid_configuration') from None


def config():
    return json.loads((ROOT / 'config.json').read_text())


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('readiness redirect is not permitted')


def cheap_ready(value):
    validate_config(value)
    version = subprocess.run(['vegeta', '-version'], capture_output=True, text=True, check=True).stdout
    # Upstream v12.12.0 main.go emits these four lines; the release retains v.
    if not re.fullmatch(r'Version: v12\.12\.0\nCommit: [^\r\n]+\nRuntime: [^\r\n]+\nDate: [^\r\n]+\n', version):
        raise ValueError('mandatory pinned Vegeta unavailable')
    for host in [value['target_origin_ip'], *value['target_domains']]:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(f'http://{host}/health', timeout=5) as response:
            if response.status != 200:
                raise ValueError('health not ready')


def run_cycle(value, trigger):
    results = ROOT / 'results'
    results.mkdir(exist_ok=True)
    with (ROOT / 'run.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history_path = results / 'history.json'
        history = json.loads(history_path.read_text()) if history_path.exists() else []
        run = uuid.uuid4().hex
        sequence = len(history)
        folder = results / run
        folder.mkdir()
        started = time.time()
        summary = {'run_id': run, 'sequence': sequence, 'trigger': trigger, 'domains': [], 'started_epoch': started, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'failed', 'mud_status': 'pending', 'attribution_status': 'pending', 'security_evidence_scope': SECURITY_EVIDENCE_SCOPE, 'failures': []}
        stage = 'configuration'
        try:
            validate_config(value)
            summary['domains'] = value['target_domains']
            stage = 'authorization'
            authorization = json.loads((ROOT / 'authorization.json').read_text())
            if authorization['config_sha256'] != fingerprint(value):
                raise ValueError('readiness authorization stale')
            stage = 'readiness'
            cheap_ready(value)
            target_file = folder / 'targets.jsonl'
            target_file.write_text(''.join(json.dumps(t) + '\n' for t in targets(value['target_domains'], run, sequence, value['mud_bad_traffic'])))
            stage = 'attack'
            raw = folder / 'results.bin'
            with raw.open('wb') as output, (folder / 'attack.stderr').open('w') as errors:
                subprocess.run(['vegeta', 'attack', '-format=json', '-targets=' + str(target_file), '-rate=50/s', '-duration=30s', '-timeout=5s', '-redirects=0', '-max-workers=100', '-name=' + run], stdout=output, stderr=errors, check=True)
            stage = 'metrics'
            report_path = folder / 'vegeta-report.json'
            with report_path.open('w') as output:
                subprocess.run(['vegeta', 'report', '-type=json', str(raw)], stdout=output, check=True)
            encoded = folder / 'requests.jsonl'
            with encoded.open('w') as output:
                subprocess.run(['vegeta', 'encode', '-to=json', str(raw)], stdout=output, check=True)
            records = []
            for line in encoded.read_text().splitlines():
                item = json.loads(line)
                url = urllib.parse.urlsplit(item['url'])
                query = urllib.parse.parse_qs(url.query)
                if query['demo_run'] != [run]:
                    raise ValueError('mismatched run ID')
                records.append({'domain': url.hostname, 'class': query['demo_class'][0], 'code': item['code'], 'error': item.get('error', ''), 'timestamp': item['timestamp'], 'latency': item['latency'], 'url': item['url'], 'method': item.get('method'), 'body': item.get('body')})
            atomic(folder / 'accounting.json', records)
            report = json.loads(report_path.read_text())
            summary['failures'] = evaluate(report, records, value['target_domains'])
            summary.update({'count': len(records), 'rate': report['rate'], 'duration_seconds': report['duration'] / 1e9, 'latencies': report['latencies'], **outcome_accounting(records), 'class_counts': {c: sum(r['class'] == c for r in records) for c in ('benign', *CLASSES)}})
            summary['rate_outcomes'] = rate_outcomes(records, value['target_domains'])
            summary['status'] = 'failed' if summary['failures'] else 'verified'
            if summary['failures']:
                summary.update(error_class='metrics_failed', error_stage=stage)
        except Exception as exc:
            error = ('configuration' if isinstance(exc, ConfigurationError) else
                     'authorization' if stage == 'authorization' else
                     'tool_missing' if isinstance(exc, FileNotFoundError) else
                     'metrics_unavailable' if stage == 'metrics' else stage + '_failed')
            summary.update(error_class=error, error_stage=stage)
            summary['failures'].append(str(exc) if isinstance(exc, ConfigurationError) else error)
        summary['completed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        atomic(folder / 'summary.json', summary)
        history.append(summary)
        atomic(history_path, history)
        atomic(ROOT / 'status.json', {**summary, 'history': history, 'scheduled_pair': scheduled_pair(history)})
        return int(summary['status'] != 'verified')


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if command == 'status':
        status = json.loads((ROOT / 'status.json').read_text())
        history_path = ROOT / 'results/history.json'
        status['history'] = json.loads(history_path.read_text()) if history_path.exists() else []
        status['timer_active'] = subprocess.run(['systemctl', 'is-active', '--quiet', 'tgen-continuous.timer']).returncode == 0
        print(json.dumps(status))
        return 0
    if command in ('run-once', 'scheduled'):
        try:
            value = config()
        except (OSError, ValueError):
            value = {}
        if not isinstance(value, dict):
            value = {}
        return run_cycle(value, 'manual' if command == 'run-once' else 'scheduled')
    if command == 'start':
        # Lifecycle calls start ONLY after its complete readiness verifier succeeds.
        try:
            value = config()
        except (OSError, ValueError):
            raise ConfigurationError('invalid_configuration') from None
        cheap_ready(value)
        atomic(ROOT / 'authorization.json', {'config_sha256': fingerprint(value), 'authorized_at': time.time()})
        subprocess.run(['systemctl', 'enable', '--now', 'tgen-continuous.timer'], check=True)
        return 0
    if command == 'stop':
        subprocess.run(['systemctl', 'disable', '--now', 'tgen-continuous.timer'], check=True)
        subprocess.run(['systemctl', 'stop', 'tgen-continuous.service'], check=True)
        (ROOT / 'authorization.json').unlink(missing_ok=True)
        return 0
    raise ValueError('expected start, stop, status or run-once')


if __name__ == '__main__':
    sys.exit(main())
