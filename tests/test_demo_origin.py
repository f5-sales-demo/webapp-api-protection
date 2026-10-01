"""Template/guest failure-path tests only; these are not live security acceptance."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import re
import subprocess
import types
import unittest
from unittest.mock import patch

TEMPLATE = Path(__file__).resolve().parents[1] / "terraform/cloud-init/origin-server.yaml"


def embedded_files():
    text = TEMPLATE.read_text()
    files = {}
    for match in re.finditer(r"^  - path: (.+)\n(?:    .*\n)*?    content: \|\n((?:      .*\n|\n)*)", text, re.M):
        files[match[1]] = "\n".join(line[6:] if line.startswith("      ") else "" for line in match[2].splitlines()) + "\n"
    return files


def guest():
    module = types.ModuleType("origin_guest")
    exec(compile(embedded_files()["/usr/local/bin/demo-origin-ready"], "guest", "exec"), module.__dict__)
    return module


class OriginTests(unittest.TestCase):
    def test_extract_compile_and_empty_terraform_variables(self):
        text = TEMPLATE.read_text()
        self.assertNotIn("cdn_simulator_host", text)
        self.assertFalse(re.search(r"(?<!\$)\$\{", text), "unescaped Terraform interpolation")
        self.assertLess(len(gzip.compress(text.encode())), 65536)
        for path, source in embedded_files().items():
            if source.startswith("#!/usr/bin/env python3"):
                compile(source, path, "exec")
            if source.startswith(("#!/bin/sh", "#!/bin/bash")):
                result = subprocess.run(["bash", "-n"], input=source.replace("$${", "${"), text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, path + result.stderr)

    def test_pinned_images_and_all_replicas(self):
        compose = embedded_files()["/opt/origin-server/docker-compose.yml"]
        for image in re.findall(r"^    image: (.+)$", compose, re.M):
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")
        g = guest()
        expected = {"juice-shop": 3001, "dvwa": 8101, "vampi": 5101, "httpbin": 8201,
                    "whoami": 8082, "csd-demo": 5001, "dvga": 5201, "restaurant": 8301}
        self.assertEqual(g.FAMILIES, expected)
        for family, start in expected.items():
            for index in range(1, 5):
                self.assertIn("  " + family + "-" + str(index) + ":", compose)
                self.assertIn('"127.0.0.1:' + str(start + index - 1) + ":", compose)
        self.assertIn('"127.0.0.1:18888:80"', compose)
        import yaml
        self.assertEqual(len(yaml.safe_load(compose)["services"]), 41)

    def test_every_compose_container_has_fail_closed_readiness(self):
        import yaml
        g = guest()
        names = set(yaml.safe_load(embedded_files()["/opt/origin-server/docker-compose.yml"])["services"])
        for failed in names:
            with self.subTest(container=failed):
                def inspect(name, *args):
                    if name == failed:
                        raise ValueError("container unavailable")
                with patch.object(g, "container", side_effect=inspect) as containers, patch.object(g, "replica"), patch.object(g, "crapi_functional"), patch.object(g, "command", return_value="1"):
                    result = g.check()
                self.assertEqual({call.args[0] for call in containers.call_args_list}, names)
                self.assertEqual(len(result["checks"]), 47)
                self.assertFalse(result["ready"])
                self.assertEqual([c["name"] for c in result["checks"] if not c["ready"]], [failed])

    def test_http_response_and_deadline_are_bounded(self):
        from unittest.mock import MagicMock
        g = guest()
        g.DEADLINE = 12
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"x" * (1024 * 1024 + 1)
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(g.time, "monotonic", return_value=10):
            with self.assertRaisesRegex(ValueError, "oversized response"):
                g.http(18888, "/community/api/v2/community/posts/recent", opener=opener)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 2)
        response.read.assert_called_once_with(1024 * 1024 + 1)
        with patch.object(g.time, "monotonic", return_value=12):
            with self.assertRaises(TimeoutError):
                g.command("docker", "inspect", "restaurant-1")


    def test_missing_tools_or_container_never_ready(self):
        g = guest()
        with patch.object(g, "command", side_effect=FileNotFoundError), patch.object(g, "http", side_effect=OSError):
            result = g.check()
        self.assertFalse(result["ready"])
        self.assertEqual(len(result["checks"]), 47)
        self.assertTrue(all(not check["ready"] for check in result["checks"]))

    def test_each_replica_failure_is_preserved(self):
        g = guest()
        for family in g.FAMILIES:
            with self.subTest(family=family):
                def replica(name, port):
                    if name == family:
                        raise ValueError("unavailable")
                with patch.object(g, "container"), patch.object(g, "command", return_value="1"), patch.object(g, "replica", side_effect=replica), patch.object(g, "crapi_functional"):
                    result = g.check()
                self.assertFalse(result["ready"])
                failures = [c["name"] for c in result["checks"] if not c["ready"]]
                self.assertEqual(failures, [family + "-" + str(i) for i in range(1, 5)])

    def initializer_transport(self, failures=None, setup=None, post_body=b'<em>Setup successful</em>!'):
        from email.message import Message
        import urllib.request
        import urllib.error
        from urllib.response import addinfourl
        from urllib.parse import parse_qs
        g = guest()
        seen, posted = [], []
        failures = failures or {}
        setup = setup if setup is not None else ("<form method='post' action='#'>"
            "<input name='create_db'><input name='user_token' value='abc123'></form>")
        owner = self
        class Transport(urllib.request.HTTPHandler):
            def http_open(self, request):
                seen.append(request)
                path = urllib.parse.urlparse(request.full_url).path
                headers = Message()
                key = (request.get_method(), path)
                if failures.get(key):
                    code = failures[key].pop(0)
                    if isinstance(code, Exception):
                        raise code
                    raise urllib.error.HTTPError(request.full_url, code, 'private token body', headers, None)
                if request.get_method() == 'POST':
                    owner.assertEqual(request.get_header('Cookie'), 'PHPSESSID=synthetic')
                    owner.assertEqual(request.get_header('Content-type'), 'application/x-www-form-urlencoded')
                    owner.assertEqual(parse_qs(request.data.decode()),
                        {'create_db': ['Create / Reset Database'], 'user_token': ['abc123']})
                    posted.append(request)
                    body = post_body
                elif path == '/setup.php':
                    headers['Set-Cookie'] = 'PHPSESSID=synthetic; Path=/'
                    body = setup.encode()
                elif path == '/login.php':
                    body = b'Login user_token'
                elif path == '/':
                    body = b'{"message":"VAmPI the Vulnerable API"}'
                elif path == '/users/v1':
                    body = b'{"users":[{"username":"synthetic"}]}'
                else:
                    body = b'{"message":"Database populated."}'
                response = addinfourl(io.BytesIO(body), headers, request.full_url, 200)
                response.msg = 'OK'
                return response
        def command(*args):
            if 'information_schema.tables' in args[-1]:
                return '1' if posted else '0'
            if args[-1] == 'SELECT COUNT(*) FROM users':
                return '5'
            return '1'
        real_builder = urllib.request.build_opener
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(g.urllib.request, 'build_opener',
            side_effect=lambda *handlers: real_builder(*handlers, Transport())))
        stack.enter_context(patch.object(g, 'container'))
        stack.enter_context(patch.object(g, 'command', side_effect=command))
        return g, seen, posted, stack

    def test_initializer_executes_real_cookie_and_form_flow(self):
        g, seen, posted, stack = self.initializer_transport()
        with stack:
            g.initialize()
        self.assertEqual(len(posted), 1)
        self.assertEqual([r.full_url for r in seen if r.full_url.endswith('/createdb')],
                         [f'http://127.0.0.1:{p}/createdb' for p in range(5101, 5105)])
        self.assertEqual(sum(r.full_url.endswith('/users/v1') for r in seen), 4)

    def test_initializer_retries_only_pre_mutation_503_and_429(self):
        g, seen, posted, stack = self.initializer_transport({('GET', '/setup.php'): [503, 429],
                                                            ('GET', '/'): [503]})
        with stack, patch.object(g.time, 'sleep') as sleep:
            g.initialize()
        self.assertEqual(len(posted), 1)
        self.assertEqual(sleep.call_count, 3)

    def test_initializer_rejects_non_form_or_missing_token(self):
        for setup in ["<input name='user_token' value='abc123'>",
                      "<form method='post'><input name='create_db'></form>"]:
            g, seen, posted, stack = self.initializer_transport(setup=setup)
            with stack, self.assertRaises(g.PhaseError) as raised:
                g.initialize()
            self.assertEqual(raised.exception.phase, 'dvwa-1:setup-get')
            self.assertFalse(posted)

    def test_mutation_http_errors_are_labeled_fatal_and_not_retried(self):
        for method, path, phase in [('POST', '/setup.php', 'dvwa-1:setup-post'),
                                    ('GET', '/createdb', 'vampi-1:createdb-get')]:
            for code in (400, 500, 503):
                g, seen, posted, stack = self.initializer_transport({(method, path): [code]})
                output = io.StringIO()
                with stack, patch('sys.argv', ['ready', '--initialize']), contextlib.redirect_stdout(output):
                    self.assertEqual(g.main(), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report['phase'], phase)
                self.assertEqual(report['http_status'], code)
                self.assertEqual(report['error'], 'HTTPError')
                self.assertNotIn('private', output.getvalue())
                self.assertEqual(sum(r.get_method() == method and r.full_url.endswith(path) for r in seen), 1)

    def test_setup_400_and_200_csrf_failure_never_become_ready(self):
        for kwargs in [{'failures': {('GET', '/setup.php'): [400]}},
                       {'post_body': b'CSRF token is incorrect'}]:
            g, seen, posted, stack = self.initializer_transport(**kwargs)
            with stack, self.assertRaises(g.PhaseError) as raised:
                g.initialize()
            self.assertIn(raised.exception.phase, ('dvwa-1:setup-get', 'dvwa-1:setup-post'))
            self.assertFalse(any(r.full_url.endswith('/createdb') for r in seen))


    def test_transport_deadline_failure_is_safe_and_phase_specific(self):
        import urllib.error
        g, seen, posted, stack = self.initializer_transport(
            {('GET', '/setup.php'): [urllib.error.URLError('secret DNS host')] * 5})
        g.DEADLINE = 1
        clock = [0]
        def sleep(seconds):
            clock[0] += seconds
        with stack, patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g.time, 'sleep', side_effect=sleep):
            with self.assertRaises(g.PhaseError) as raised:
                g.initialize()
        self.assertEqual(raised.exception.phase, 'dvwa-1:setup-get')
        self.assertEqual(clock[0], 1)
        self.assertFalse(posted)
        self.assertNotIn('secret', json.dumps(g.diagnostic(raised.exception)))

    def test_concurrent_cookie_jars_never_cross_sessions(self):
        from concurrent.futures import ThreadPoolExecutor
        from email.message import Message
        from http.cookiejar import CookieJar
        from urllib.response import addinfourl
        import threading
        import urllib.request
        barrier = threading.Barrier(2)
        class Transport(urllib.request.HTTPHandler):
            def __init__(self, session):
                super().__init__()
                self.session = session
            def http_open(self, request):
                headers = Message()
                if request.data is None:
                    headers['Set-Cookie'] = 'PHPSESSID=' + self.session + '; Path=/'
                    body = self.session.encode()
                    barrier.wait(timeout=5)
                else:
                    self_test.assertEqual(request.get_header('Cookie'), 'PHPSESSID=' + self.session)
                    self_test.assertEqual(request.data.decode(), self.session)
                    body = b'ok'
                response = addinfourl(io.BytesIO(body), headers, request.full_url, 200)
                response.msg = 'OK'
                return response
        self_test = self
        def session_flow(session):
            g = guest()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()), Transport(session))
            token = g.http(8101, '/setup.php', opener=opener)
            return g.http(8101, '/setup.php', data=token.encode(), opener=opener)
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(list(pool.map(session_flow, ['a1', 'b2'])), ['ok', 'ok'])

    def test_verified_dvwa_seed_skips_reset_but_all_vampi_replicas_initialize(self):
        g, seen, posted, stack = self.initializer_transport()
        with stack, patch.object(g, 'dvwa_seeded', return_value=True):
            g.initialize()
        self.assertFalse(posted)
        self.assertEqual(sum(r.full_url.endswith('/setup.php') for r in seen), 4)
        self.assertEqual(sum(r.full_url.endswith('/createdb') for r in seen), 4)

    def test_stale_or_missing_database_is_fatal(self):
        g = guest()
        with patch.object(g, "container"), patch.object(g, "replica"), patch.object(g, "crapi_functional"), patch.object(g, "command", return_value="0"):
            result = g.check()
        self.assertFalse(result["ready"])
        self.assertEqual([c["name"] for c in result["checks"] if not c["ready"]],
                         ["dvwa-database", "restaurant-database", "crapi-database"])

    def test_static_health_cannot_substitute_for_functional_response(self):
        g = guest()
        for family, port in g.FAMILIES.items():
            with self.subTest(family=family), patch.object(g, "http", return_value='{"status":"healthy"}'):
                with self.assertRaises((ValueError, KeyError, TypeError, AttributeError)):
                    g.replica(family, port)
        with patch.object(g, "http", return_value="<html>healthy</html>"):
            with self.assertRaises(ValueError):
                g.crapi_functional()

    def test_unhealthy_and_restarting_containers_fail(self):
        g = guest()
        for state in [{"Running": False}, {"Running": True, "Restarting": True}, {"Running": True, "Health": {"Status": "starting"}}]:
            with patch.object(g, "command", return_value=json.dumps(state)), self.assertRaises(ValueError):
                g.container("crapi-identity", health=True)

    def test_timeout_is_nonzero_machine_readable_and_redacted(self):
        g = guest()
        output = io.StringIO()
        with patch("sys.argv", ["demo-origin-ready", "--timeout-seconds", "1"]), patch.object(g.time, "monotonic", side_effect=[0, 2]), patch.object(g, "check", return_value={"ready": False, "checks": []}), contextlib.redirect_stdout(output):
            self.assertEqual(g.main(), 1)
        self.assertFalse(json.loads(output.getvalue())["ready"])

    def test_pinned_runtime_layout_and_wsgi_entrypoint(self):
        files = embedded_files()
        compose = files["/opt/origin-server/docker-compose.yml"]
        import yaml
        services = yaml.safe_load(compose)["services"]
        for index in range(1, 5):
            service = services[f"restaurant-{index}"]
            self.assertEqual(service["working_dir"], "/app")
            self.assertEqual(service["command"][:2], ["uvicorn", "main:app"])
        import ast
        import shlex
        argv = shlex.split(next(line for line in files["/opt/origin-server/vampi-gunicorn.sh"].splitlines()
                                if line.startswith("exec gunicorn")))
        module, export = argv[argv.index("0.0.0.0:5000") + 1].split(":")
        self.assertEqual(module, "config")
        self.assertIsInstance(ast.parse(export, mode="eval").body, ast.Name)
        # Exact pinned image config.py exports the framework's App; 2.14.2 AbstractApp.__call__
        # delegates to self.app(environ, start_response). Attribute syntax is rejected by Gunicorn.
        pinned_export = ast.parse("vuln_app = connexion.App(__name__, specification_dir='./openapi_specs')")  # codespell:ignore connexion
        self.assertEqual(export, pinned_export.body[0].targets[0].id)
        self.assertEqual(pinned_export.body[0].value.func.attr, "App")
        self.assertIn("import_app('config:vuln_app')", files["/opt/origin-server/vampi/Dockerfile"])
        self.assertNotIn("pip install", files["/opt/origin-server/vampi-gunicorn.sh"])
        self.assertIn("--require-hashes", files["/opt/origin-server/csd-demo/Dockerfile"])
        self.assertNotIn("https://", files["/opt/origin-server/csd-demo/templates/checkout.js"])
        for key, source in files.items():
            if key.endswith("Dockerfile"):
                for image in re.findall(r"^FROM (\S+)", source, re.M):
                    self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")

    def test_gevent_runtime_dependencies_are_complete(self):
        files = embedded_files()
        requirements = files["/opt/origin-server/csd-demo/requirements.txt"]
        # Gunicorn 26.2.0 PyPI metadata declares packaging in its gevent extra.
        self.assertIn("gunicorn[gevent]==26.2.0", requirements)
        self.assertIn("gevent==26.9.0", requirements)
        self.assertIn("packaging==26.0 --hash=sha256:b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", requirements)
        self.assertIn("import gunicorn.workers.ggevent", files["/opt/origin-server/csd-demo/Dockerfile"])
        self.assertIn("import_app('app:app')", files["/opt/origin-server/csd-demo/Dockerfile"])
        for line in requirements.splitlines():
            if line and not line.startswith("#"):
                self.assertRegex(line, r"^[\w.\[\]-]+==[\d.]+ --hash=sha256:[0-9a-f]{64}$")
        import yaml
        packages = yaml.safe_load(TEMPLATE.read_text())["packages"]
        self.assertNotIn("dool", packages)
        self.assertIn("sysstat", packages)
        self.assertIn("iotop", packages)

    def test_required_provisioning_failure_stops_execution(self):
        provision = embedded_files()["/usr/local/bin/demo-origin-provision"]
        self.assertIn("set -Eeuo pipefail", provision)
        self.assertIn("timeout 1200 docker compose build", provision)
        self.assertIn("--initialize --timeout-seconds 300", provision)
        compose = embedded_files()["/opt/origin-server/docker-compose.yml"]
        self.assertNotIn("alembic upgrade head", compose)
        self.assertEqual(provision.count("alembic upgrade head"), 1)
        # Run the actual guest provisioner; intercept first host operations to avoid mutations.
        shell = provision.replace(". /usr/local/lib/cloud-init-helpers.sh",
                                  'log_phase() { printf "%s\\n" "$*"; }; '
                                  'sed() { return 0; }; systemctl() { return 17; }')
        result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True)
        self.assertEqual(result.returncode, 17)
        self.assertIn("failed origin provisioning aborted", result.stdout)
        self.assertNotIn("all origin replicas and functional dependencies verified", result.stdout)

    def test_nginx_activation_precedes_fallible_initialization(self):
        provision = embedded_files()["/usr/local/bin/demo-origin-provision"]
        # Execute the recorded activation and readiness phases without touching the host.
        activation = provision[provision.index("ln -sf /etc/nginx/sites-available/origin-server"):
                               provision.index("# GitHub commits/main receipt")]
        readiness = provision[provision.index("/usr/local/bin/demo-origin-ready --initialize"):]
        shell = "set -Eeuo pipefail\n" + activation + readiness.replace(
            "/usr/local/bin/demo-origin-ready", "demo_origin_ready")
        receiver = r'''
        site_enabled=0; default_removed=0; loaded_site=default
        ln() { site_enabled=1; printf '%s\n' "site-enabled"; }
        rm() { default_removed=1; printf '%s\n' "default-removed"; }
        nginx() {
          [ "$*" = '-t' ] || return 19
          [ "$site_enabled $default_removed" = '1 1' ] || return 20
          printf '%s\n' "nginx-test"
          return "$validation_status"
        }
        systemctl() {
          printf '%s\n' "systemctl $*"
          case "$*" in
            'enable nginx') ;;
            'restart nginx') loaded_site=origin ;;
            *) return 21 ;;
          esac
        }
        demo_origin_ready() {
          printf '%s\n' "readiness $* loaded=$loaded_site"
          [ "$loaded_site" = origin ] || return 22
          return 23
        }
        log_phase() { printf '%s\n' "phase $*"; }
        '''
        for validation_status, expected_status, expected in [
            (0, 23, ["site-enabled", "default-removed", "nginx-test",
                     "systemctl enable nginx", "systemctl restart nginx",
                     "readiness --initialize --timeout-seconds 300 loaded=origin"]),
            (17, 17, ["site-enabled", "default-removed", "nginx-test"]),
        ]:
            with self.subTest(validation_status=validation_status):
                result = subprocess.run(
                    ["bash", "-c", f"validation_status={validation_status}\n" + receiver + shell],
                    text=True, capture_output=True)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertEqual(result.stdout.splitlines(), expected)
        self.assertEqual(provision.count("systemctl restart nginx"), 1)

    def test_serialized_migration_uses_runtime_workdir(self):
        source = embedded_files()["/usr/local/bin/demo-origin-provision"]
        migration = next(line for line in source.splitlines() if "alembic upgrade head" in line)
        # Execute the real migration invocation with a non-mutating argv receiver.
        receiver = '''
        set -eu
        timeout() { shift; "$@"; }
        docker() {
          [ "$1 $2 $3 $4 $5 $6 $7" = "compose run --rm --no-deps --workdir /app restaurant-1" ] || return 19
          shift 7
          [ "$1 $2" = "sh -euc" ] || return 20
          [ "$3" = 'alembic upgrade head; python -c "import main"' ] || return 21
          echo serialized-migration
        }
        '''
        result = subprocess.run(["sh", "-c", receiver + migration], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("serialized-migration", result.stdout)

    def test_crapi_paginated_posts_contract(self):
        g = guest()
        # Synthetic contract fixtures, not claims of observed live crAPI responses.
        valid = {"posts": [{"id": "seed-id", "title": "seed-title", "content": "seed-content"}],
                 "total": 1, "next_offset": None, "previous_offset": None}
        invalid = [valid["posts"], {}, {**valid, "posts": []},
                   {**valid, "posts": ["healthy"]}, {**valid, "posts": [{}]},
                   {**valid, "total": True}, {**valid, "total": 2},
                   {**valid, "next_offset": "1"}, {**valid, "previous_offset": -1}]
        def responses(page):
            return ["<html>crAPI</html>", '{"token":"synthetic"}', json.dumps(page),
                    '{"products":[{"id":1}],"credit":100}', '{"items":[]}']
        with patch.object(g, "http", side_effect=responses(valid)) as http:
            g.crapi_functional()
            self.assertEqual(http.call_args_list[2].args[1],
                             "/community/api/v2/community/posts/recent?limit=1&offset=0")
        for page in invalid:
            with self.subTest(page=page), patch.object(g, "http", side_effect=responses(page)):
                with self.assertRaises(ValueError):
                    g.crapi_functional()



if __name__ == "__main__":
    unittest.main()
