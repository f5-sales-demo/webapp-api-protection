# Origin and traffic remediation tasks

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>

Implementation issues: [origin-server](https://github.com/f5-sales-demo/origin-server/issues/710), [traffic-generator](https://github.com/f5-sales-demo/traffic-generator/issues/711).

Detailed operational receipts remain in the private lifecycle state directory. Baseline failures are immutable evidence and are not acceptance. Completion requires source, installed, and live checks; all incomplete tasks remain open. Preserve shared DNS, namespace identity, private state, schema fixtures and unrelated worktrees. CSD remains disabled.

## Current acceptance status

This section is authoritative for the resumed repair round. Historical sections below preserve earlier observations;
they do not establish current acceptance. All T01–T16 tasks remain incomplete.

Current source is origin `3a62623`, generator `3583ccf`, and
WAAP `6f6ee5c`. Terraform runtime, root/module/namespace pins and lock files select provider 13.0.2;
its exact spec provenance matches enriched specs v10.0.0. WAAP required CI is green. Source checks pass
82 origin tests with 69 subtests, 156 generator tests with nine subtests, and 334 WAAP tests with
396 subtests/one environment skip. All nine applications and 33 native ports remain declared.

The latest complete rendered matrix is origin `fa7156d`: 66 passing browser receipts, no missing
workflow/layer entries, and 315 screenshots reviewed with full-size key pages. Private evidence:
`private-browser-matrix-1791055912416669296/`. Final acceptance remains false; timeout-source changes
require another matrix and final fresh/merged deployment checks. DVWA session retention, all 15 SQLi
and 18 XSS payloads, RESTaurant BOPLA restoration, coupon controls, and SQLMap native dispatch passed
focused qualification on their recorded sources. Earlier failed evidence remains failed.

A full ten-minute native stress retry on generator `2400574` completed all declared dispatches but
failed for 35 client cancellations. ApacheBench reports show variable response-length errors during
mitigation; native workers completed, but that does not establish successful coverage. Private evidence:
`resume-focused-kraken-native/`. New source requires retained completed native wrk/hey/Vegeta/ApacheBench
reports, retains scheduled burst reports, extends sustained hey timeouts and uses native ApacheBench
variable-length mode. Regressions reject empty/missing/native-error reports independently of counts.

Origin nginx, both WAAP route timeouts and the existing origin-pool idle timeout were updated through
saved ownership-checked plans. The first two costly-query retries remain failed. A later receipt was
only dispatch-qualified because its response contract was missing; it is not accepted as complete.
Generator now requires JSON containing nonempty systemUpdate results for every single/batch element,
rejecting partial batches, GraphQL errors and wrong-content 200s. Installed `4e6a784` failed the
stricter focused retry under `resume-focused-dvga-costly-query/`. Continuous traffic is stopped while
the single shared boundary is occupied and will restart afterward.

No complete catalog pass is accepted. Remaining work includes complete native stress/nested/connection
behavior, isolated signup/OTP/video fixtures and broad mutation restoration, two accepted full catalog
passes, control attribution, sustained load, merged immutable installation, ownership-scoped clean rebuild,
stop/restart/reboot recovery, unchanged apply and zero-action plan. All T01–T16 tasks remain open.
CSD remains disabled. The provider13 full live plan succeeds but its two custom_data VM replacements
remain unapplied pending completed source/workflow gates.

Native two-operation DVGA probes passed JSON identity through a replica (70 seconds) and nginx
(40 seconds). Private recovery logs showed the thirty-second recovery timer restarting busy replicas.
Origin `50e94c0` now requires 900 seconds of sustained unresponsiveness before restart, preserving long
operations; a synthetic regression verifies grace, eventual recovery and healthy reset. Source tests pass
81 tests/69 subtests. Immutable install is running; published strict-response qualification remains open.

Direct published DVGA probe returned HTTP 504 stream timeout at 30 seconds independently of the
generator proxy. Provider13 schema identifies `more_option.idle_timeout` as the active-stream timeout,
distinct from route deadline and origin-pool idle time. WAAP now exposes `lb_stream_idle_timeout_ms`
through both owned listeners. The saved ownership-checked provider13 apply updated only those two
listeners, with zero additions/destroys and the installed schema preserved. Source verification passes
335 tests/396 subtests with one environment skip. Direct/paced long-query retries are running; earlier
504 runs remain failures. The latest generator separates native-report verification to repair required
CI branch-count lint.

WAAP `4eceab2` commits the active-stream timeout; live API confirms `more_option.idle_timeout=600000`.
Queued expensive work from prior failed probes remained active, so the interrupted retry was preserved
and only four ownership-verified DVGA containers were restarted without deleting their seeded data.
Installed generator `7f68b3f` also refuses empty timing samples as efficiency evidence. One strict batch
sequence is now running against the complete timeout chain. Complete acceptance remains open.

The repaired published costly-query retry returned HTTP 200 for the baseline and two-operation batch,
with every nonempty systemUpdate JSON assertion passing. Recovery logs confirm the busy replica remains
running. Larger batches/mixed sequence remain in progress and are not yet accepted.

Generator now rejects undeclared server errors even when a dispatch matches; explicit expected HTTP 500
cases require their status-specific content assertion. Native worker report and deadline regressions pass.
Source checks pass 153 tests and nine subtests. Terraform plan regressions pass five cases including active
stream timeout on both protected listeners. The published baseline/two/five-operation DVGA responses passed
all JSON assertions; ten-operation and mixed checks remain running.

Strict repaired DVGA run remains failed: baseline/two/five-operation responses passed full JSON
assertions, but the ten-operation request did not finish before the 900-second scenario deadline and
mixed batch was not launched. Preserve this timeout receipt; it is not full application/scenario acceptance.
Continuous traffic is being restored on latest immutable source while remaining long-query and fixture
contracts are repaired.

Current native stress qualification on installed `02b10b1` is past four minutes with zero transport
failures/cancellations and a completed retained scheduled-burst report. Its full ten-minute native-report
acceptance remains pending. Source crAPI video mutation repair snapshots original media/name/parameters,
restores through native APIs and verifies exact identity; missing recovery fails acceptance. Source tests
pass 156 tests/nine subtests plus lint/type checks; installed/live video qualification remains pending.

Latest full native stress iteration completed all declared dispatches/native reports but remains failed
for twenty client cancellations at timed-worker termination. Private receipt: `resume-focused-kraken-native/`.
The repaired video fixture now returns native HTTP 200 with media and matching identity. Focused video
qualification failed before mutation: prerequisite/request client cancellations made its reachability
probe time out, so no command launch or restoration acceptance is claimed. Preserve that receipt under
`resume-focused-crapi-video-restoration/`. Continuous traffic restart is in progress on installed `143dde9`.

Focused native crAPI video mutation retry on `3583ccf` passed all three intended dispatches/response
checks and exact original-media/name/conversion restoration, with nine requests, zero transport failures
and zero cancellations. Private receipt: `resume-focused-crapi-video-restoration/`. This qualifies the
video-command workflow only; admin-video deletion and broader fixtures remain open. Source corrects
403/429 shell classification to agree with structured mitigation receipts. Earlier reachability failure
remains failed. Continuous traffic restart is in progress.

Costly GraphQL route now explicitly disables automatic upstream retries, preserving exactly one
execution of each expensive batch. Provider13 plan tests pass both protected listeners and existing
header behavior (five cases); WAAP source passes 335 tests/396 subtests with one environment skip.
Saved ownership-checked live plan changes only the two existing listeners; apply passed with zero additions/destroys.
Current rendered matrix on origin `3a62623` has 33 passing browser receipts/no failures; full acceptance
and screenshot review remain pending. Fixture exporter rerun idempotence passed after native video media
repair. Continuous catalog has thirteen passing receipts/no failures; no full pass is accepted.

Source fixture authentication now retains per-path outcome/status receipts and fails transport errors
before dependent scenario setup; mitigated requests remain distinct from rejection or timeout. Source
verification passes 158 generator tests/nine subtests and repository lint. Installed qualification is
pending. Refreshed origin matrix currently has 56 passing browser receipts/no failures. Costly batch
retry with no upstream retries has passing baseline and two-operation JSON responses; larger batches
remain running and are not yet acceptance.

Current origin `3a62623` matrix completed with all 66 passing browser receipts and no missing workflow/layer
entries (`private-browser-matrix-1791063748644233125/matrix-receipt.json`). All 315 screenshots were reviewed
as contact sheets and key pages; private manual review remains final_acceptance=false with a limitation
for Juice Shop about/supporting-media loading indicators. The rendered slice is provisional, not fresh
final delivery. Native fixture exporter reruns remain stable.

No-retry costly DVGA sequence also reached its 900-second deadline before ten-operation response
completion; mixed batch was not launched. Baseline/two/five JSON responses passed, but the full scenario
remains timeout with one cancellation. Preserve this failure under `resume-focused-dvga-costly-query/`.
Latest setup-outcome source is being immutably installed and continuous traffic restarted.

## Previous continuation evidence

Current source candidates are origin `fa7156d` and generator `bc328c6`. Terraform pins are being refreshed
from pushed commits and verified archive/installer digests. Source verification passed 79 origin tests with
69 subtests and 143 generator tests with nine subtests. Required CI for the latest heads is pending.
The three application manifests declare nine applications with 33 native serving ports.

The last complete origin matrix (`9347439`) passed 66 browser receipts and all declared workflow/layer entries.
Its 315 screenshots were reviewed provisionally. Five landing crawl layers passed 28 checks each. These
receipts remain candidate evidence; a same-source final matrix and fresh/merged installation are required.
Fixture exporter reruns retained counts and object identities, but broad mutation restoration remains incomplete.

Origin `987c161` passed immutable installation with seven-day DVWA session retention. Fresh synthetic
sessions returned authenticated SQL content on every native replica and both HTTPS published domains.
Generator `5caa791` then passed focused dispatch/response checks for all 15 SQLi and 18 XSS payloads, with
zero transport failures or cancellations. The herd scenario passed 303 requests with native completion.
Private receipts are retained under `resume-focused-dvwa-restoration-latest/` and the lifecycle
private install directory.

The same focused run failed RESTaurant BOPLA despite successful fixture restoration: unsupported `Admin`
and `Manager` roles returned application HTTP 500. The failure remains failed. Origin `3f4df8a` adds an
idempotent native adapter that returns HTTP 422 before database mutation for unsupported roles, preserving
valid-role mass assignment. Its immutable installation and focused retry passed six intended role payloads, profile restoration,
zero transport failures and zero cancellations; prior failures remain failed.

Generator `a4d6c7d` fixes OTP receipt counters lost in a background subshell and removes unsupported
full-keyspace feasibility claims. A deterministic shell regression first reproduced the failure, then passed
with both batches counted. This does not repair registration/OTP fixture isolation or establish full coverage.
The latest installed generator is `bc328c6`; source and installed provenance were checked independently.

The interrupted full catalog baseline recorded 76 scenarios, with 62 passing and 14 failing. No complete
catalog pass is accepted. Earlier rapid, API fuzz, ZAP and Nikto focused successes remain bound to their
recorded sources. Failed stress, crAPI fixture and DVGA timeout evidence is preserved. Continuous traffic is active and enabled on generator `70dacf7` after complete startup readiness.
No accepted full catalog pass is claimed.

Coupon retry on `70dacf7` passed the valid seeded coupon control, exact invalid-code HTTP 500/empty JSON
contract and three injection payloads, with zero transport failures/cancellations. A blocked control cannot
satisfy this contract. Other focused crAPI passes include mechanic reports/discovery, unauthenticated order
probes and JWT confusion. Private evidence: `resume-focused-crapi-latest/` and `resume-focused-coupon-retry/`.
The origin type regression was repaired after required CI failed; latest CI remains pending.

Remaining gates include complete native stress/nested/connection behavior, all mutation restoration,
two accepted full catalog passes, final control attribution and sustained load, merged immutable installation,
ownership-scoped clean rebuild, stop/restart/reboot recovery, unchanged apply and zero-action plan.
All T01–T16 tasks remain open. CSD remains disabled.

Latest continuation: generator `bc328c6` restores ten-minute stress duration, waits for native/nested
workers, bounds Vegeta queues, requires native tools plus scheduled bursts and Lua diversity, extends
paced SQLMap response deadlines, and removes unsupported video-execution claims. Source checks pass
147 tests and nine subtests. The first full native stress retry (`6386a69`) remains failed with ApacheBench
errors and thousands of client cancellations; its owned process group was interrupted after preserving
failure evidence. Corrected retry is running under `resume-focused-kraken-native/`; continuous traffic
is stopped while that single shared boundary is occupied. Origin `fa7156d` is immutably installed with
green required CI. Its current matrix passed all 66 browser receipts with no missing workflow/layer entries
(`private-browser-matrix-1791055912416669296/matrix-receipt.json`). All 315 screenshots were
reviewed as contact sheets, with full-size key pages checked; the private manual review remains
final_acceptance=false. The second native stress retry remains failed for ApacheBench exit 119 and
two client cancellations; its owned process group was interrupted with evidence retained. SQLMap
focused qualification passed all three native invocations and intended endpoint/payload requirements,
230 requests, zero transport failures and zero cancellations (`resume-focused-sqlmap-retry/`). Continuous traffic restart is in progress on `bc328c6` after releasing the focused boundary.
WAAP `5eb8ad8` required CI is green; final coverage/rebuild gates remain open.

DVGA timeout continuation: origin `4dc6f02` derives a 600-second proxy read timeout from the shared
manifest only for DVGA. Generator `d2cba83` preserves the costly query client timeout. WAAP `e9a4f88`
applies that route timeout to both HTTP and HTTPS listeners. Source checks pass 80 origin tests with
69 subtests, 147 generator tests with nine subtests and 334 WAAP tests with 396 subtests/one environment
skip. Immutable origin/generator installation passed. A saved ownership-checked Terraform plan initially
exposed stale schema inputs; it was not applied. The corrected plan preserved the installed schema and
updated only the two owned listeners (zero additions/destroys). Focused costly-batch qualification is
running under `resume-focused-dvga-costly-query/`; continuous service is stopped for that boundary.

The first costly DVGA retry after route/nginx timeout repair remained failed: baseline returned JSON,
but batches returned HTTP 504 near 30 seconds. The configured route timeout was verified live. A second
ownership-checked saved plan updated only the existing origin pool idle timeout to 600000 ms, preserving
its name/ID, schema, namespace and other resources (zero additions/destroys). Generator `45800ca` additionally
drains finite stress burst/mixed loops, retains ApacheBench against the owned HTTP companion, and extends
mixed-request client deadlines. Its installed digest is verified. Second costly-query qualification is
running; no final application/catalog/rebuild acceptance is claimed.

Ecosystem version verification: the prior showcase runtime and both lock files selected xcsh 12.0.2,
while Registry/GitHub latest was 13.0.2. Root, HTTP-LB module and namespace pins now select exactly
13.0.2. Registry installation verified signing key 7282C542DC88E217; binary build commit matches
release 6d488749cd8995795a91e43b9a1892866fd73f87. Provider tracked spec-release pin is v10.0.0 /
ac024ccbfb8b9f84412813f3e2ab9f5821937ef2; its SHA256 exactly matches the provider publication receipt
(0e278b4afb598ac8628ac74dca6a1b2831cd8607de1d26f56e72e3461a7440c7). Registry lock checks include
Linux amd64 and Mac arm64. Terraform validate and 334 source tests/396 subtests passed with one
environment skip. The private full live plan succeeded on 13.0.2; only the two VM custom_data changes
require replacement. That rebuild plan remains unapplied. Previous 12.0.2 applies retain their original
provider evidence and are not relabeled. The latest costly-query receipt passed dispatch but lacks
status-specific response assertions; its completeness is not accepted until response contracts reconcile.

## Historical observations

Earlier revisions and measurements below are retained as evidence of their original outcomes.

Expanded origin `671fbe167ea015363297e3ed9e068934c933cd55` passed immutable installation and required CI.
Focused BOLA qualification at generator `3edcadd371784d336645de59ed82ad222c6e94de` passed all six dispatch/response
requirements, all five synthetic profile restorations, zero transport failures and zero cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791011143124566516/receipt.json`. The prior duplicate-phone run remains
failed: its five application 500s were not accepted. Expanded probes target synthetic privileged accounts. All 33 supported
native HTTP workflows passed after the immutable reinstall. Full rendered/workflow/catalog acceptance remains open.

BOLA rerun on `ba75fb9394e34c42e416cca5e7e29390b326165d` passed without registration requests, with
all five profile restorations and zero transport failures/cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791011321925464310/receipt.json`. Self-profile source now measures CPU,
memory, disk, network, TCP states and descriptors before/during/after load. Installed `d3596fbcf6e9105dff0489db0ebd17b0d2e6bbb0`
passed 300 requests across all nine applications, actual concurrency, resource phases and minimum duration, with zero
transport failures/cancellations. Private receipt: `resume-focused-profile/pass-focused-1791011590430151567/receipt.json`.
Ephemeral workload qualification passed all 20/50/100 batches, 170 completed requests across all nine applications,
measured fresh connections and cleanup, with zero transport failures/cancellations. Private receipt:
`resume-focused-ephemeral/pass-focused-1791011683915132895/receipt.json`. This does not establish port exhaustion
or replace complete catalog and sustained-rate acceptance.

Connection comparison passed installed on `a095743c633fb132171906d93b1d84b5b0d08c8e`: 100 requests on one
reused connection and 100 on fresh connections, valid content and zero transport failures/cancellations. Private receipt:
`resume-focused-churn/pass-focused-1791011861378822523/receipt.json`. Installed `708e5bcb696f18351b0fc0ca4a89073664c98ce8`
reverified retained churn/profile/ephemeral workload evidence with the stricter all-samples gate; all passed. That
reverification qualifies the verifier against existing evidence and is not a new full catalog pass. Private receipt:
`workload-reverification-708e5bc.json`. Continuous service restart is being verified.

Nested BOLA child qualification passed through the shared pacing boundary on `fe3b7b65de395a10b400b0d1c46c4efcba0ee3df`,
with 22 attributed child requests, every declared dispatch/response requirement and profile restoration. Private receipt:
`resume-focused-nested/pass-focused-1791012333150743754/nested-restaurant-exploits/restaurant-exploits--02-bola-profile/receipt.json`.
Browser children now propagate validated opaque markers; native tool resolution skips owned wrapper chains. Aggregate
reports reject foreign receipt symlinks. Installed nested scanner/browser and complete parent stress remain open.

Installed ZAP marker qualification passed on `cc3d1a01113327aff9279491ac0fc0205f2fe75b`: the pinned native
scanner loaded its replacer configuration and dispatched the intended access request to its own child receipt through
the shared boundary. Private receipt: `resume-focused-zap-marker/pass-focused-1791012924444458872/receipt.json`.
This proves attribution only; full scanner actions/completion and Nikto attribution remain open. Earlier CI repair
revision `8838ec2` passed its Super-Linter job, but its workflow was canceled by a newer push; current required CI is pending.

Catalog reconciliation removed 699 blanket HTTP 500 allowances across 64 scenarios. All 164 entries remain.
Application crashes now fail response acceptance; intentional server-error cases require explicit case-specific evidence.
Focused historical passes retain their original sources and outcomes. Current source passes 114 tests and nine subtests;
current installed catalog restart and required CI are pending. Generator `dc8da02` completed green required CI.
Startup readiness now rejects arbitrary HTTP 405 on declared healthy pages. Full per-case status/content reconciliation remains open.

Slow-header evidence now records every write round and explicit peer/tool errors. The first diagnostic run remains
failed, with 42 successful writes and eighteen TLS EOF errors across twenty bounded connections. Private receipt:
`resume-focused-slow-evidence/pass-focused-1791013215755636419/receipt.json`. A new verifier distinguishes recorded
peer closure from timeout/tool failure without attributing a WAAP control. Installed retry passed as a bounded probe with 42 sent headers and eighteen recorded peer-closed connections,
complete three-round evidence, duration and cleanup. Private receipt:
`resume-focused-slow-evidence/pass-focused-1791013379582960007/receipt.json`. No WAAP control is attributed; the prior
failed iteration remains failed. Full connection-scenario scope reconciliation and control attribution remain open.

Positive response verification now requires declared content type and JSON identity while retaining only assertion
booleans. RESTaurant BOLA requires the actual synthetic target username and changed phone value in every positive
mutation response. Wrong-content 200 and wrong-actor regressions fail. Installed qualification passed all response identities,
22 dispatches and profile restoration with zero transport failures/cancellations. Private receipt:
`resume-focused-bola-fixtures/pass-focused-1791013673736185449/receipt.json`. All 59 Python files pass mypy and
repository-configured Pylint. Continuous startup is being verified; complete catalog/workflow acceptance remains open.

Origin rendering crawl retained 27 screenshots and 28 checks, with one Juice Shop failure: seven Socket.IO 400
responses and eight console errors. Private run `private-render-1791013788038158000` remains failed. Direct origin
clients had an empty forwarding-header affinity key and sessions moved across replicas. Source `b91654a31f5f42e9906f81bae7225c98a8785875`
adds a remote-address fallback; 43 source tests and 68 subtests pass. Its digest-checked immutable installer passed.
Focused polling continuity now passes five of five native and five of five nginx sessions; Chromium observes an actual
WebSocket frame without a socket error. Fresh origin rendering run `private-render-1791014120430315000` passed all 28 content checks across nine
applications and retained 27 screenshots. Its contact sheet was reviewed; individual rendered workflow review remains
open. The receipt correctly retains accepted=false because authenticated workflow acceptance is incomplete. Published
serving-layer acceptance and
published serving-layer acceptance remain open. The reviewed contact sheet is a preliminary visual review only.

Native crAPI authentication exposed a seeded-role mismatch: the backend returns ROLE_PREDEFINE while the frontend
user-route guard only recognized ROLE_USER and ROLE_ADMIN. Vehicle API returned its seeded object, but the dashboard
rendered no vehicle and Community/Shop returned to dashboard. The failed browser workflow remains failed evidence.
Origin `53a54904fb70291c10c1de3636353376bc6a6cc2` adds a narrow seeded-role frontend compatibility adapter and fails
if the pinned upstream guard changes. Source checks pass 44 tests and 68 subtests; immutable installation and browser
qualification are in progress. Full workflow acceptance remains open.

Seeded-role crAPI adapter installed successfully. Chromium rendered vehicle details and image, Community posts and
Shop products; native menu clicks and deep-link refresh worked. The same run remains incomplete because automatic
chatbot state requests returned 404. Provisioning incorrectly routed chatbot requests to identity and omitted the chatbot
dependency. Source now declares an immutable native chatbot image and functional uninitialized-state readiness. Origin
`18fd2a27ce87a6e934af315868f458076e881eb3` passes 45 tests and 69 subtests; installation is pending. Accumulated
synthetic community posts remain a fixture-cleanup failure. Full crAPI/browser acceptance remains open.

The pinned chatbot dependency installed and its real uninitialized-state readiness passed. Diagnostic browser views
rendered vehicle, Community and Shop with native navigation and refresh, with the previous chatbot 404 eliminated.
The reusable stricter browser verifier at origin `522d0d5` nevertheless fails on external map transport requests.
Its five application view assertions pass, but both transport-failure runs remain failures. Private receipts:
`private-crapi-verifier-1791015610823458000/receipt.json` and `private-crapi-verifier-1791015662983845000/receipt.json`.
Origin `522d0d5b12cbd33ebb4eac558ef2233e1f1f0e62` passed the immutable installer. Installed verifier digest
matches committed source in `installed-crapi-verifier-digest.json`; strict browser transport failures remain open.
Full rendered completeness remains open.
Origin source passes 45 tests and 69 subtests; generator source passes 119 tests and nine subtests.

Community data-exposure scenario now reads pinned native seeded posts without creating random duplicates. It requires
a nonempty posts response and exact content type/JSON keys at the real recent-posts endpoint. Installed qualification
passed on `e1fde3384ba1425ddc961719f982ef7cc8ea8d2c`, with actual GET/query dispatch and response assertions,
zero transport failures/cancellations. Private receipt:
`resume-focused-community-read/pass-focused-1791016048498089525/receipt.json`. Historical duplicate data remains
a cleanup failure. Generator source passes 121 tests and nine subtests and all sixty Python files pass type checking.

The stricter seeded response contract also rejects empty or malformed posts lists; every observed post must contain
nonempty ID, title and content. Installed retry passed actual dispatch and all nonempty object assertions with zero transport failures/cancellations.
Private receipt: `resume-focused-community-read/pass-focused-1791016261901811208/receipt.json`. All sixty Python
files pass mypy and repository-configured Pylint. Full catalog completion, merged
artifacts, clean rebuild, sustained-rate/control proof and repeated Terraform apply remain open.

Current installed supported HTTP workflows passed nine checks on origin nginx and on both WAAP domains over HTTP
and HTTPS, using refreshed private fixtures. These are limited supported workflow checks, not complete rendered
application acceptance. Generator `4aa6a2c` required CI is green; origin `522d0d5` required CI is green. Current
continuous service is enabled and running on the exact generator source with no failures in its early current pass.
Full two-pass catalog, rate/control attribution, authenticated rendered workflows, mutation cleanup and Terraform
convergence remain outstanding. No T01–T16 task is marked complete from these narrower receipts.

A bounded 120-second rate window on generator `4aa6a2c` observed 197.28 aggregate requests/sec, 177.65 benign
requests/sec, 100 percent completed benign success and zero benign transport failures. Private receipt:
`rate-window-receipt.json`. This is an observation before clean deployment, not final sustained-rate acceptance.
Multi-client source now retains its 100 correlated identity echoes and adds twenty clients each rotating through all
nine application content contracts (280 total requests). Source checks pass 122 tests and nine subtests; focused
installed qualification passed 280 requests: 100 identity echoes and twenty dispatches to each of nine apps,
per-client content/cleanup evidence, zero transport failures/cancellations. Private receipt:
`resume-focused-multiclient-all/pass-focused-1791016780937147850/receipt.json`. Original randomized deep paths and all workload semantics remain open.

The remaining eighteen scenario-level blanket HTTP 500 classifications were removed to keep application crashes
distinct from expected outcomes. Request contracts already reject broad 500 allowances. VAmPI mutation scope and
shared-account restoration remain open. Current generator source preserves all 164 scenarios and passes 122 tests
with nine subtests; immutable install completed and continuous readiness/start verification is pending.

Installed verifier runtime audit found that origin provisioning installs the browser scripts but does not provision
Node/Playwright. Script digest equality is verified; installed browser runtime acceptance is incomplete. The successful
origin crawl used the operator browser host and cannot substitute for a reproducible installed verifier runtime.
Pinned runtime provisioning is an explicit remaining T09/T13 gate.

Origin `a936a2d3b72c25d47ed986aeb3909d2071031422` provisions a digest-pinned Playwright 1.63.0 runtime
with a matching integrity-locked package and source-installed verifier scripts. Package audit reports zero vulnerabilities;
46 source tests and 69 subtests pass. Immutable runtime installation passed; Origin-host locked-runtime content verification passed all 28 checks across nine applications and retained 27
screenshots. Private output: `/opt/origin-server/private-browser-1791017479808857095`. Accepted remains false because
full authenticated workflow and screenshot acceptance are incomplete; Installed crAPI workflow retry remains failed with five rendered checks passing and two external-map transport
failures. Private receipt: `/opt/origin-server/private-browser-1791017603361585040/receipt.json`. Origin runtime CI
is green. This is not complete rendered workflow acceptance.
Private installer receipt: `remediation-immutable-origin-1791017354705763175/receipt.json`. The earlier 1.55.0 candidate was
replaced after its package audit identified a fixed browser-download certificate issue; it is not an accepted runtime.

Scenario and nested child receipts now carry immutable source commit and archive digest in addition to entrypoint
digest. Aggregate reports reject mismatched artifacts/revisions even when a shell entrypoint did not change.
Source regression rejects adapter revision mismatch; 123 tests and nine subtests, mypy and configured Pylint pass.
Installed nested provenance qualification passed child dispatch/restoration, matching source commit/archive
and the aggregate report. Private child receipt:
`resume-focused-nested/pass-focused-1791017796681530580/nested-restaurant-exploits/restaurant-exploits--02-bola-profile/receipt.json`. Full nested stress and all catalog semantics remain open.

Exact request/workload endpoints are reconciled into the target matrix for 125 scenarios. Validation now rejects an
exact executable target missing from its scenario matrix. Root discovery and intentional-negative probes remain separate
from hosted application identity acceptance. All 164 entries remain; source checks pass 124 tests and nine subtests,
mypy, configured Pylint and changed-file pre-commit. Installed catalog completed; continuous startup is pending.

WAAP candidate deployment inputs now pin the exact installed origin/generator commits, archive digests and both
installer digests. Its vendored manifest matches pinned origin content, including the chatbot dependency, and outputs
carry generator source provenance plus the origin Python installer digest. Credential-free WAAP checks pass 306 tests
with one existing skip. These are candidate pins; merged-source installation and ownership-checked Terraform rebuild
remain open. Current generator CI is green and its early full pass has ten verified receipts with no failures.

Origin browser runtime now performs exact ownership-checked cleanup, rejects symlink evidence destinations and retains
a separate failed runtime receipt. Controlled installed failure left zero owned verifier containers. Source provenance
records the exact immutable commit, archive and installer in origin installation and browser runtime receipts. Origin
`4a557deb9c2f953b08739f93a1c444cfec9745b9` passed immutable installation; 50 source tests and 69 subtests,
type/lint checks pass. Full rendering failures remain failures. Continuous generator restart is being verified.

Quiet-period diagnostic retry on origin `a2a3e4149cf136cea0ecd8859eaa9d2ea2d38270` remains failed. Both
external-map requests report net::ERR_FAILED in subframes, not ERR_ABORTED navigation cancellation. All five native
application view checks pass; full rendered acceptance is still false. Private receipt:
`/opt/origin-server/private-browser-1791019546050759919/receipt.json`. Immutable installer and provenance passed;
WAAP candidate pins are reconciled with this revision and credential-free tests pass.

The current interrupted full pass reached fourteen receipts, thirteen verified and one failed rapid-browser scenario.
The retained browser checkpoint had only its first identity and browser_closed=false; a source repair now closes and
persists evidence in finally on early failure. Seven focused Node tests pass. Installed rapid retry was interrupted after confirmed blank 200 pages and navigation timeouts on
`7e7ae5e43bc9eeb71c3cd118900e456fa9f449f4`; the failed pass remains failed.

Latest rapid-browser iteration `resume-focused-rapid-final/pass-focused-1791019820323884692/receipt.json` remains
failed and interrupted before all 360 actions completed. It retains blank 200 screenshots and navigation timeouts;
mitigated requests are distinct from rendered routes. The terminal scenario receipt recorded zero transport failures
and zero cancellations. Continuous startup is being verified on the immutable candidate. No failed pass was relabeled.

DVGA batch coverage now requires single systemUpdate, exact 2/5/10 expensive batches and the mixed batch.
Generic arrays cannot establish expensive-operation dispatch. Source regression rejects wrong operations and sizes;
125 tests and nine subtests, mypy/Pylint and changed-file checks pass. Installed catalog is updated; live completion
remains open because the native 20–50 second operation and batch duration exceed existing client/upstream timeouts.
The application delay was preserved. Full catalog/rebuild acceptance remains open.

Origin evidence retention now evicts only completed owned browser runs by age/size and monitors the active cap and
deadline. Source tests preserve active/unrelated paths and reject unowned eviction. Origin `83beebf` installed
successfully. Subsequent header-scope correction keeps workflow tracking headers off third-party frames; its diagnostic
run no longer reported the prior map transport errors but hit a pending-request deadline and remains failed.
Origin `8f9c5e7` passes 53 tests and 69 subtests; Immutable installation passed. The locked-runtime crAPI retry passed all five rendered view checks with zero
errors; its five screenshots were manually reviewed for vehicle image/map, Community and Shop before/after refresh.
Private receipt: `/opt/origin-server/private-browser-1791021207307010849/receipt.json`. Earlier failures remain failed.
This qualifies native login and read-only views; signup, workshop mutations, fixtures and all published browser layers
remain open. No browser failures were suppressed.

DVWA CSRF source no longer prints unconditional exploit success. Origin `0bc63fa` provisions a dedicated
synthetic tgen_csrf account and per-domain real sessions; managed traffic uses that identity for a distinct password
change and requires original-password authentication restoration evidence. Shared admin identity is preserved.
Origin source passes 54 tests and 69 subtests; generator source passes 125 tests and nine subtests. Immutable install
and focused mutation/restoration verification are running; this task remains incomplete until observed checks pass.

First dedicated DVWA seed failed because pinned native users.user_id has no default. That fixture failure remains
failed. Origin source now supplies a noncolliding native ID and tests require it. Corrected origin `acc37c3` immutable
installation is running; full CSRF qualification remains pending. The scoped mutation cannot be accepted until real
fixture authentication and restoration both pass.

Corrected dedicated CSRF fixture export passed after native user_id repair. The first focused mutation dispatched
change/restore but failed authenticated restoration; its receipt remains failed. Source now follows login redirects
and requires Logout content instead of assuming any redirect proves authentication. Fixture was regenerated before
retry; Installed focused qualification on `4aa9c10` passed distinct password mutation, changed-password authentication,
original-password restoration/authenticated content, both intended dispatches and zero transport failures/cancellations.
Private receipt: `resume-focused-csrf-scoped/pass-focused-1791022734105439066/receipt.json`. Shared admin fixture
was preserved. Earlier seed and restore failures remain failed evidence. No exploit success is printed without observed mutation
and changed-password authentication.

Scoped CSRF also restores its dedicated account on early script exit and retains failed cleanup. The final source
`506d542` is installed; Focused normal-flow repeat passed both dispatches, real mutation/authentication/restoration, and zero transport
failures/cancellations. Private receipt: `resume-focused-csrf-scoped/pass-focused-1791022987278269891/receipt.json`. Prior accepted normal-flow source remains its own receipt and does
not qualify interruption behavior. Shared admin and unrelated fixtures remain preserved.

Juice Shop native browser diagnostic passed ten assertions: translated products/images, native login, seeded basket,
about/contact/recycle/complaint/scoreboard and observed WebSocket frames, with no recorded errors. Source-controlled
verifier is now included in the locked origin runtime; Origin `bbc2520` immutable installation passed, and locked-runtime verification passed all ten checks with zero
errors. Its eight screenshots were manually reviewed for product images, labels, supporting pages and seeded basket.
Private receipt: `/opt/origin-server/private-browser-1791023435742027870/receipt.json`. Published browser layers
are now running. This does not complete checkout or all serving-layer workflows. Full application acceptance remains open.

Published Juice Shop browser runs passed ten workflow checks on HTTPS www; HTTP www and HTTP api remain failed
with Socket.IO error and incomplete product-image assertion. All other declared workflow views rendered. These HTTP
failures are not accepted. Private outputs: `private-browser-juice-1791023514147314482`,
`private-browser-juice-1791023534348957858`, and successful HTTPS `private-browser-juice-1791023551194020428`.
HTTPS api also passed all ten checks in `private-browser-juice-1791023566571231582`. Serving-layer completeness remains open.

HTTP companion listener lacked the declared WebSocket routes. An ownership-checked saved plan updated only that
listener; apply failed provider readback because route priority materialized DEFAULT from null. Failed apply receipt is
preserved. Source now emits DEFAULT explicitly. The repair saved plan had zero resource actions and applied successfully
(0 added/changed/destroyed). This is a targeted repair check, not final full Terraform convergence. Origin verifier
`d534acf` waits for terminal product images before assertion; Immutable installation passed. Both HTTP domains now passed ten rendered workflow checks with zero errors;
private outputs: `private-browser-juice-1791024250681555708` and `private-browser-juice-1791024271883735139`.
Both HTTPS domains passed earlier on the prior verifier source. Final same-source all-layer acceptance remains open.

Checkov parsing failed the existing multiline FQDN boolean validation. The expression was reformatted with the operator
on the preceding line, preserving validation semantics; intact scanner retry is running. HTTP WebSocket source repair
is verified through saved ownership-checked plan/readback and browser checks, but final full Terraform convergence
remains open. Continuous traffic is enabled and running.

Final same-source Juice Shop browser runs passed ten assertions each on both HTTP and HTTPS domains, including
product images and WebSocket frames. Private outputs: `private-browser-juice-1791024443400890439`,
`private-browser-juice-1791024464796403123`, `private-browser-juice-1791024481190821058`, and
`private-browser-juice-1791024496081781694`. Earlier HTTP image/socket failures remain failed. These workflow checks
do not complete checkout, mutation cleanup or native replica-browser acceptance.

Three focused rapid-browser iterations remain failed or interrupted. The latest retained receipt is
`resume-focused-rapid-final/pass-focused-1791009776937631086/receipt.json`. It includes two tool cancellations and failed
response/action assertions. Response evidence shows WAAP 403 on product APIs, application scripts and images while the
main document returns 200. Mitigated navigation is recorded separately from rendered content; blocked assets do not prove
complete application rendering. No focused iteration is accepted as a full browser or application pass.

Outstanding gates include fixture snapshot/restoration and distinct BOLA actors; complete original workload semantics;
nested scanner/browser attribution; all rendered authenticated workflows and serving layers; merged immutable installs;
one ownership-scoped clean rebuild; two accepted full catalog passes; sustained rate/control attribution; restart/reboot;
and unchanged Terraform apply followed by a zero-action plan. Continuous operation alone cannot satisfy those gates.

| Task | Status | Dependencies | Acceptance criteria | Issue / PR | Source revision | Verification receipt |
| --- | --- | --- | --- | --- | --- | --- |
| T01 — Record baseline | In progress | none | Capture routes, replicas, fixtures, rendered failures, catalog, deployed digests, Terraform ownership and shared identities; retain private receipt. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Private remediation-baseline/receipt.json; live baseline captured, preservation reconciliation pending |
| T02 — Application manifest | In progress | T01 | Exactly nine applications reconciled across declaration, docs, landing, outputs and traffic. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c`; generator `43e7f73` | Nine-app source and installed landing inventory pass; merged/fresh installation pending |
| T03 — Coverage matrix | In progress | T02 | Native/published routes, replicas, assertions, fixtures and scenarios; no missing/orphan entries. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c`; generator `43e7f73` | 66-receipt workflow/layer matrix complete; scenario scope and mutation contracts incomplete |
| T04 — Unified provisioning | In progress | T02 | Both roots consume one immutable origin installer including existing pinned dependencies and repairs. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | Digest-checked installer installed; standalone and fresh Terraform convergence pending |
| T05 — Prefix handling | In progress | T04 | Assets, links, forms, API, redirects, cookies and SPA routes retain application prefixes. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | Native/published workflow and landing crawls pass; final merged rebuild pending |
| T06 — Application defects | In progress | T05 | All nine applications pass specified authenticated/seeded/rendered workflows and replica checks. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | Private matrix 1791044273150348894; 315 screenshots reviewed; broad mutation/fresh proof pending |
| T07 — DVWA payload coverage | Open | T03,T08 | All 15 SQLi and 18 XSS payloads reach authenticated DVWA; preserve stable scenario ID mappings. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T08 — Repeatable fixtures | In progress | T04 | Synthetic fixture reruns produce no duplicates; scoped mutations restored; blocked setup cannot suppress launches. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | Private fixture-rerun 1791046618208888465 passed counts/IDs twice; broad scoped restoration incomplete |
| T09 — Content verifier | In progress | T03 | Landing reconciliation, navigation, rendered assets/images, console/network, forms and authentication fail closed; screenshots reviewed. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | Wrong-content/broken/lazy-image regressions and five landing crawls pass; merged proof pending |
| T10 — Serving layers | In progress | T06,T09 | All native replicas, origin nginx, both domains HTTP/HTTPS; identity/type correct; wrong-content 200 fails. | <https://github.com/f5-sales-demo/origin-server/issues/710>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c` | All native workflow replicas/origin/four published layers pass; fresh deployment gate pending |
| T11 — Scenario receipts | In progress | T03,T07 | 164 entries across 22 suites; intended method/path/payload and browser/connection action observed apart from setup/filler. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Generator `43e7f73` | 164/22 retained; native ZAP/API-fuzz/Nikto focused checks pass; full catalog remains failed/incomplete |
| T12 — Outcome attribution | In progress | T11 | Explicit negative cases; mitigation, rejection, fixture/tool/transport failure and timeout distinguished. | <https://github.com/f5-sales-demo/traffic-generator/issues/711>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Generator `43e7f73`; WAAP `2ecb381` | Exact response/provenance/rotation gates implemented; final attributed control proof pending |
| T13 — Lifecycle integration | In progress | T04,T08,T10,T12 | Existing lifecycle/control verbs preserved; immutable inputs/digests/URL maps recorded; startup gated on complete readiness. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c`; generator `43e7f73` | Lifecycle verbs and artifact pins retained; fresh installation and traffic readiness acceptance pending |
| T14 — Repair loop | In progress | T13 | Source checks, installed and live gates pass on committed immutable configuration; failed receipts retained. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Origin `b30656c`; generator `43e7f73` | Active repair loop; source and focused installed receipts retained; no complete acceptance |
| T15 — Clean rebuild | Open | T14 | One ownership-checked destroy/absence/preservation/recreate from committed source; no manual fixture setup. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |
| T16 — Final acceptance | Open | T15 | Two complete catalog passes; 200 aggregate RPS within 5%; 180 benign equally split/rotated across nine apps; >=99% success, zero transport failures; attributed controls; stop/restart/reboot; unchanged apply then zero plan; continuous service running. | <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>; PRs: <https://github.com/f5-sales-demo/origin-server/pull/711>; <https://github.com/f5-sales-demo/traffic-generator/pull/713> | Pending | Pending |

## Historical verification snapshot

Origin and generator changes are committed in draft PRs. Origin source checks: seven Python regressions, rendered wrong-content and broken-image regression, full pre-commit, Terraform validation, and Docker builds passed.

Generator: 42 tests plus nine subtests, Ruff and full pre-commit passed. WAAP baseline: 330 tests passed with one existing skip.

Candidate origin guest readiness passed. An origin nginx crawl passed 43 content checks across all nine applications.
Full authenticated workflow acceptance, screenshot review, every native rendered replica, both WAAP domains, full
scenario dispatch contracts, immutable merged installation, successful clean rebuild and repeat apply remain open.
Traffic was stopped during repair. No Terraform destroy has run.

Failures retained privately include the original prefix defects, HTTPBin UTF-8 build failure, RESTaurant source-path failure, rendered adapter gaps, and incompatible legacy Werkzeug middleware. Failed iterations are not acceptance.

## Repair receipts

DVWA login, security selection, seeded SQL lookup and reflected-XSS benign workflow passed through both HTTPS domains. Origin tests: 35 passed and 68 subtests passed. Generator tests: 42 passed and nine subtests passed. WAAP tests: 306 passed with one existing skip.

A fresh 46-second traffic interval measured 197.38 aggregate requests/sec, 100% benign success and zero benign transport failures. Prior 97.6% and 98.5% intervals remain failed receipts. Full catalog acceptance has not completed on this candidate.

The latest HTTPS content crawl passed all checks except two browser-cancelled default Juice Shop logo requests while the CTF logo replaced them. A source adapter is being updated to start with the configured logo. Screenshots are retained privately; complete authenticated workflow and replica acceptance remain open.

Continuous traffic is enabled and running. The scoped saved WebSocket route plan applied one load-balancer update, no create or destroy. No clean Terraform rebuild or zero-change repeat apply has run for these candidate sources.

Both public HTTPS domains passed authenticated DVWA login, security selection, seeded SQL lookup and reflected-XSS benign workflow. CSD replica state matched. A later 46-second traffic interval passed at 197.38 aggregate requests/sec with 100% benign success and no benign transport failures.

The clean-install review added explicit nginx cache creation, adapter image provenance for DVGA recovery and manifest-derived readiness. Origin has 35 passing tests and 68 passing subtests; generator has 43 passing tests and nine passing subtests. All three PRs remain drafts because required delivery and acceptance tasks remain open.

## Outstanding delivery gates

Source request contracts cover 34 of 164 scenarios, with eleven additional CSD browser contracts and seven connection
probe adapters. The remaining scenario contracts and installed verification prevent full catalog acceptance. Source CI
and rendered diagnostics do not complete T11, T15 or T16.

No clean rebuild, two accepted complete catalog passes, unchanged repeat apply, reboot recovery or merged-artifact installation has been claimed. All three implementation PRs remain drafts. Current source, candidate installation and failed iterations are retained separately in private receipts.

The current installer rerun passed every native readiness check. The remaining rendered failure was isolated to duplicate crAPI chatbot state requests; a regression now requires both source occurrences to be guarded before login. The updated build and cross-domain rendered verification are still in progress.

The last complete installer attempt failed its readiness deadline after deployment. This remains a failed installer receipt. A subsequent focused native readiness probe passed after correcting the accepted DVGA operation name; it does not convert the failed attempt into acceptance. Continuous traffic was restored and is enabled and running on the current candidate.

The latest full rendered run was blocked by WAAP 403 responses. Complete rendered, authenticated and scenario acceptance, clean rebuild, repeat apply and merged installation remain outstanding. These failures prevent completion; source tests and passing short traffic intervals are insufficient.

## Resumed verification

Native readiness passed again on every application replica. The running generator retained zero current failures and near-100% benign success at resumption.

Dispatch verification now distinguishes prerequisite requests from execution requests, retains request attribution from
enqueue time, and verifies matching method, endpoint, body class and required counts. Four API-protection scenarios have
explicit action contracts. Endpoint-denial and rate-limit targets were corrected to the configured HTTPBin paths.
Missing fixtures produce failed private receipts without terminating the rest of the catalog. An existing contract alone
cannot mark a dispatch verified, and an incomplete contract matrix cannot mark a catalog pass accepted.

Intentional negative endpoints are tested by scenarios, while startup probes declared healthy application pages. Failed browser and installer evidence from earlier iterations remains retained. Full 164-scenario reconciliation and final rebuild acceptance remain open.

Installed dispatch receipts verified all declared schema-violation, shadow-endpoint, configured endpoint-denial and
configured rate-limit actions. The first DVWA pass dispatched every payload but failed two login redirects. After
refreshing real origin-authenticated sessions, a separate pass verified all 15 SQLi and 18 reflected-XSS launches with
no transport failures. The failed pass remains failed evidence.

Eight DVGA scenario contracts were added around valid JSON GraphQL documents, batch size, operations and payload classes. Their installed dispatch verification is still pending. A GraphQL helper transport regression verifies arbitrary query quotes and variables survive JSON construction unchanged.

## Current evidence and remaining failures

The corrected nonmutating crawl produced 58 passing HTTPS content checks across both domains. Its 56 rendered
screenshots were reviewed; application identity, images, Swagger/ReDoc and navigation were visible. Screenshot review
also found DVGA's start-over link, which resets application state; it was added to the declared mutation paths and
excluded from read-only crawling. A final crawl is pending that manifest adjustment.

Installed API-protection dispatch contracts and a refreshed authenticated DVWA payload pass succeeded. All 33 preserved
DVWA payloads dispatched. The first stale-session pass remains failed. Eight DVGA action contracts are implemented, but
a focused batch/recursion pass timed out and recorded cancellations; it is failed evidence, not successful application
rejection. Cancelling tool requests now causes scenario failure.

Generator source tests currently pass 58 tests and nine subtests. Full pre-commit passes. Native application readiness passed at resumption. CI repair, remaining catalog action contracts, every required authenticated workflow, HTTP serving-layer checks, immutable merged installation, clean rebuild, restart/reboot recovery and final repeat apply remain open.

A later native DVGA batch/recursion qualification failed and left an orphan task proxy after its controller stopped. Its private receipt remains failed. Proxy recovery now records PID, process start ticks and exact source script; tests reject PID reuse and command mismatch. The exact orphan proxy was removed without signalling unrelated processes, and continuous traffic was restarted.

Current generator source validation passes 61 tests and nine subtests plus full pre-commit. Four API-protection contracts and refreshed DVWA payload contracts have installed evidence. Eight DVGA contracts are implemented but have not passed installed acceptance. Full 164-scenario contracts, application workflow completeness and final clean rebuild remain open.

Issued-authentication workflow checks passed 17 native replica checks for Juice Shop, DVWA, VAmPI, RESTaurant
customer/chef roles and crAPI vehicle/community/workshop/MailHog content. Those checks also passed through origin nginx
and both WAAP domains over HTTP and HTTPS. The reusable verifier is committed in origin-server; complete browser
interactions and fixture mutation cleanup remain separate open requirements.

The extended reusable verifier passed 33 native application checks and nine application checks at each of origin nginx,
both WAAP HTTP domains and both WAAP HTTPS domains. HTTPBin's positive POST body was corrected to the deployed demo_id
schema; malformed bodies remain attack scenarios. These checks prove the implemented authentication and seeded content
assertions, while full browser interaction coverage and fixture cleanup remain outstanding.

The corrected nonmutating HTTPS crawl passed 56 content checks after excluding the DVGA start-over reset link. Earlier
passing-looking crawls that visited reset links are retained as diagnostic evidence, not nonmutating acceptance. Source
dispatch contracts currently cover 14 of 164 scenarios; seven connection scenarios have separate probe receipts. The
remaining action contracts prevent full catalog acceptance.

The all-nine application workflow verifier passed 33 native checks, plus nine checks at origin nginx and each WAAP
HTTP/HTTPS endpoint. crAPI source dispatch contracts now cover its 15 scenarios; installed crAPI action qualification
remains pending. Current source action contracts cover 29 of 164 scenarios, with seven additional connection probe
scenarios. Complete action coverage and final rebuild acceptance remain open.

A focused immutable crAPI qualification passed five action contracts: 20 unauthenticated mechanic-report probes, mechanic listing, three NoSQL coupon operators, 21 unauthenticated order probes and seven forged-dashboard requests. No transport failures or tool cancellations were recorded. The other ten crAPI scenario contracts still require installed qualification.

Browser/CSD contracts now require the exact manifest step assertions and successful browser cleanup, independent of network request counts. CSD remains display-only and disabled for enforcement. Source execution contracts cover 34 scenarios, plus eleven CSD browser action contracts and seven connection probes; the remaining catalog reconciliation is open.

## Current browser and connection qualification

Generator revision `db23bf793a3f20999a3ce38ca21818b53d1a8c8a` passes 67 tests and nine subtests, targeted mypy,
Pylint and pre-commit. Browser receipts now require captured screenshots with passed assertion status, exact action
steps and successful browser cleanup. A request contract cannot be overridden by a browser receipt; interrupted receipt
files fail closed. Connection verification requires the complete TLS offering matrix and certificate validation, or the
bounded slow-header writes, duration and connection cleanup for the declared probe.

The first installed eleven-scenario CSD qualification at revision `b36e7878f35f112ce783c309aa1dbbbb5df0737e` failed.
Its screenshot adapter expected the wrong receipt field. The adapter is corrected in the later source revision, and the
original receipt remains failed. Seven scenarios also recorded client cancellations, including product assets and
Socket.IO polling; those require separate remediation. CSD enforcement remains disabled and the browser suite makes
no detection claim. Corrected installed qualification is in progress; final acceptance remains open.

## Latest installed qualification

Source request contracts cover 36 scenarios; eleven CSD browser contracts and seven bounded connection adapters are
additional. The catalog remains 164 scenarios across 22 suites. Generator Python validation passes 68 tests and nine
subtests, Ruff, mypy and Pylint; full pre-commit passes. Required CI Ruff formatting/import/constant defects were repaired
in `b0587019a8b9bd76f6365260d37d6274a7923258`; current CI remains pending.

VAmPI authentication qualification passed all sixteen declared requirements, and mass assignment passed all eight
payload contracts at installed revision `f6b3a932653ec6026e4c7b306344a02a57a04b3e`, with no transport failures or
cancellations. These establish launch evidence, while fixture cleanup and complete application acceptance remain open.

CSD qualification at `2b3af044cde787195db0cc2a24a36453f5b50f63` passed ten scenarios but failed high-volume navigation:
HTTP 200 did not produce the expected login controls. The 56 screenshots were reviewed privately; its high-volume
screenshots were blank. Earlier failed adapter and cancellation runs remain failed. Declared browser cleanup now
separately counts only established Socket.IO polling sessions closed after the cleanup marker; assets and execution
cancellations still fail. CSD remains display-only with enforcement disabled. Full rendered acceptance remains open.

The installed bounded connection qualification passed six adapters: three port/protocol probes and three TLS matrices,
including certificate validation and cleanup. Slow-header qualification failed because fewer than sixty header writes
completed across twenty connections. Its receipt remains failed; the cause and expected peer-close behavior require
reconciliation before acceptance.

Native browser credential stuffing submitted all fifteen DVWA credential pairs, but failed overall on one cancellation.
Registration/contact submitted neither required action in its first corrected run; the native form response wait timed
out. Source now uses paired response/click waits, dismisses the deployed welcome controls and parses the synthetic
arithmetic captcha without evaluating JavaScript. Installed retry is in progress. Direct request fallbacks are removed.

## Current source and serving state

Latest generator candidate is `394c7f9fbdc7b81eed470459c5c639122fc5e433`. Its source checks pass 68 Python tests,
nine subtests, 24 browser unit tests, Ruff format/check, mypy, Pylint and full pre-commit. The AWS-only headed-browser
unit test is excluded outside its declared AWS runtime; this does not count as live application acceptance. CI is pending.

The latest native form retry still failed registration: both required registration requests were absent, while both
contact submissions completed with HTTP 201. A cancellation also failed the scenario. Native controls are now used for
question selection and submission, and the failure remains open. The prior disabled-control and pointer-interception
receipts remain failures. Continuous traffic was restored after focused qualification and verified enabled and running on the immutable candidate.
No merged-artifact acceptance, clean Terraform rebuild, complete catalog pass or repeat apply has been performed.

The restored service reported revision `394c7f9fbdc7b81eed470459c5c639122fc5e433`, enabled and running, with
2,769 of 2,769 benign requests successful in its initial status sample. This is liveness evidence, not sustained-rate or
full-catalog acceptance.

## Full source contract matrix

Generator revision `12ccf1fd1a3fe099ef7e910a1b57cc85e399a4fd` declares execution evidence for every one of the
164 scenarios across 22 suites: 144 request contracts, eleven CSD browser contracts, seven connection adapters and two
aggregate report contracts. Catalog validation rejects missing contracts. Source tests pass 78 tests and nine subtests;
Ruff, mypy, Pylint and full pre-commit pass. This completes source declaration only; T11 remains in progress until
installed actions, prerequisites, output semantics and complete catalog passes qualify.

Native browser registration/contact now each dispatch twice through actual UI controls with zero transport failures or
cancellations after closing the security-question menu and draining pending requests. The first fresh requests returned
201; repeat registration of existing synthetic accounts returned 400 while both contact actions returned 201. Those
responses remain distinct application outcomes, and repeatable account cleanup remains open.

Installed exact contracts passed VAmPI OWASP (22 requirements), Juice Shop SQL login (five payloads twice), SQL search
(nineteen queries), NoSQL (twenty-one payloads), and RESTaurant mass assignment (six requirements). RESTaurant command
injection first failed raw ampersand transport; source now URL-encodes the complete parameter, and a separate run passed
all nine payloads. DVWA SQL first failed quoting before dispatch; argument-based encoding repaired the source and a
separate pass dispatched all six SQL requirements. Web SSRF passed all fifteen exact payloads after header/body argv
repair. Prior failed runs remain failed evidence.

Real origin-issued DVWA sessions now feed all fourteen installed DVWA scenarios. Focused dispatch passed command
injection, file inclusion, reflected XSS and open redirects. Weak-session dispatch generated twenty probes but returned
no captured IDs; this remains incomplete workflow evidence. Scanner tool wrappers now retain binary digests, intended
invocation matches and completion status independently of request dispatch. Aggregate reports require successful
current-pass dependency receipts and source hashes rather than static coverage claims.

Outstanding acceptance includes meaningful workload/concurrency receipts, native scanner completion, per-request
expected responses, scoped fixture restoration, full browser content assertions and all live application layers.
Immutable full-catalog qualification is starting; no accepted full pass, merged installation, clean Terraform rebuild,
sustained-rate acceptance or repeat apply is claimed.

## Installed matrix repair loop

The complete source matrix remains 144 HTTP action contracts, eleven CSD browser contracts, seven connection adapters
and two aggregate reports. Source validation now passes 83 tests and nine subtests; request-response joins, scanner
binary/completion receipts, workload concurrency/connection checks, and wrong-content 200 regression remain enforced.

Native application workflow rerun passed all 33 checks. Installed scraper dispatch passed after pending request drainage,
with no transport failures or cancellations. Hydra qualification passed 99 credential payloads on each of DVWA, Juice Shop
and VAmPI after HTTPS routing and native module-option ordering repair. A measured workload ramp passed 300 requests
across all nine apps at worker levels 1, 10 and 20, with zero transport failures or cancellations. Later source additionally
requires correct application identity and actual measured connection/concurrency behavior; installed rerun is pending.

The first full-matrix candidate pass was interrupted for source repairs after fifteen scenarios, with twelve accepted
launches and three failed browser/Hydra scenarios. It remains an incomplete failed pass. A later pass recorded an
incorrect response expectation for six intentional shadow endpoints: all actions dispatched, but expected 404s were
excluded. Source now explicitly declares 401/404 for those exact negative endpoints. The failed receipt remains failed.
Continuous catalog qualification is running on the next immutable candidate; no complete accepted pass is claimed.

T03/T11 remain in progress because declared contracts do not by themselves prove application workflows, native scanner
completion, expected outcome semantics, scoped fixture restoration, browser screenshots or final clean-deployment
acceptance. All clean rebuild, merged installation, sustained 200-RPS, restart/reboot and repeat-apply gates remain open.

## Post-matrix acceptance hardening

Generator source now passes 85 tests and nine subtests. The source execution matrix still contains all 164 scenarios:
144 request contracts, eleven CSD browser contracts, seven connection adapters and two aggregate report contracts.
Declared response outcomes are joined to exact matched actions, and each required dispatch needs a terminal response.
Aggregate report receipts must match the current source digest. Native scanner invocation/completion, actual workload
concurrency/connection reuse and wrong-content HTTP 200 checks remain separate acceptance assertions.

Installed follow-up passed both the corrected intentional shadow endpoint statuses and a 300-request workload ramp at
levels 1/10/20 across all nine applications, including content identity, actual concurrency and connection reuse, with no
transport failures or cancellations. Hydra dispatched 99 credential guesses per DVWA/Juice Shop/VAmPI endpoint after
native module-option repair. Native workflow rerun passed all 33 application checks. Failed/incomplete full catalog
passes remain failed and were not relabeled. Continuous traffic is running on the next candidate while CI is pending.

Nested worker verification now fails a zero-exit child without observed action receipts. Concurrent child attribution,
fixture mutation restoration, scanner outcome semantics, declared cache behavior, complete rendered navigation and
all required application workflows remain open. No clean rebuild, accepted complete catalog pass, sustained final rate,
merged installation, reboot recovery or zero-change repeat apply is claimed.

## Current candidate checks

Source tests pass 86 tests and nine subtests after extending benign success to require application identity and content
type. Required payload dispatches now need corresponding terminal responses. The latest candidate sources retain the
complete 164-entry matrix; continuous and focused runs preserve failures independently. CI remains pending.

A stronger installed workload ramp passed all nine application identities and measured concurrency/connection reuse
at levels 1, 10 and 20 across 300 requests, with no transport failures or cancellations. The corrected six intentional
shadow endpoint contracts passed their observed 401/404 response expectations. A later full pass failed native browser
credential stuffing on cancellations despite all fifteen credential submits; source now waits for login page resources
before submission and focused retry is pending. These failures are not accepted coverage.

Latest generator source is `1039987738cda33f57cb25d32f616152cddbd4de`. Remaining source-to-live delivery gates
include complete catalog execution, mutation fixture restoration, precise scanner output semantics, nested attribution,
rendered content/workflow completeness, all serving layers, merged artifact installation, clean rebuild, rate/control
qualification and unchanged Terraform repeat apply. No task is completed from source contract presence alone.

## Dynamic cache qualification

Generator revision `83a7386cd5cad4a1ea5f01df28e6a32f733b7458` passes 87 tests and nine subtests, mypy, Pylint,
Ruff and full pre-commit. The query-string and Accept-Encoding scenarios preserve their stable IDs and now verify the
deployed dynamic-bypass behavior, correct application identity and response type, echoed query isolation, and decoded
content instead of requiring cache HIT on authenticated dynamic applications.

Installed qualification passed 72 query-isolation requests including every original user/search/version value, twenty
paired UUID values and alpha/bravo cross-contamination controls. Encoding qualification passed all 24 declared encoding
and no-header cases. Both receipts had zero transport failures and cancellations. Static cache policy qualification,
remaining CDN workload semantics and full catalog acceptance remain open. Continuous traffic is being restarted on this
immutable candidate; no accepted complete pass or final rebuild qualification is claimed.

## Current acceptance receipts

Source tests now pass 89 tests and nine subtests. All 164 scenario execution contracts remain mandatory. Benign traffic
success additionally requires declared content/type identity, each counted payload requires a terminal response, and
undeclared unmatched 500/502/503/504 or transport failures fail the response gate. CDN shell assertions now fail their
process instead of only printing a failure. No failed receipt was relabeled.

The installed dynamic-bypass query and encoding contracts passed 72 and 24 requests respectively, with preserved query
values, application identity and decoded response content. Native credential-stuffing retry passed all fifteen browser
form submits with no transport failure or cancellation after waiting for page resources before submission. Continuous
traffic is enabled and running on the current immutable candidate; the current pass has eight verified scenarios so far.
CI, full catalog acceptance, complete application workflows and the Terraform rebuild/zero-change gates remain open.

## Current full catalog progression

Generator source is `67409fef99dea9635b1cc518f787c4511bc25b90`; validation passes 92 tests and nine subtests,
Ruff, mypy and required pre-commit. The full source matrix is 164 entries across 22 suites, with mandatory request,
browser, connection or report execution evidence. No catalog entry was removed.

The latest continuous pass reached twenty receipts, nineteen accepted launches and a failed baseline load scenario.
Baseline wrk cutoffs cancelled 158 outstanding requests; it remains failed evidence. Source now uses a fixed-count
completion baseline with measured concurrency, connection reuse, per-request content identity and no abandoned
requests. Focused installed qualification is in progress. Remaining baseline randomized-path coverage stays open.

Dynamic query/encoding qualification passed 72 and 24 action/content assertions respectively. Native registration,
contact, credential stuffing, Hydra, scraper, SQL/NoSQL, VAmPI and focused DVWA/RESTaurant dispatch repairs retain their
individual installed receipts. Those do not complete all application workflows or all catalog contracts.

CI source type/format findings in payload-encoding and CDN regression tests were repaired. Current CI is pending.
Continuous traffic will restart after focused qualification. Complete fresh catalog passes, mutation restoration, nested
attribution, scanner semantics, complete rendered workflows, merged installation and clean Terraform acceptance remain
open. T11 is in progress; failed and interrupted passes were not relabeled.

A separate installed baseline completion qualification passed all 200 requests with valid content, actual concurrency
and connection reuse, zero transport failures and zero cancellations. Non-GET bypass qualification passed all nine
request/response/cache-control requirements with zero transport failures/cancellations. Continuous traffic is restarting
on `67409fef99dea9635b1cc518f787c4511bc25b90`; complete catalog and final deployment acceptance remain open.

## Current repair round

Generator source `cd8dfcb4c50d21dc5d32529bdf7259d51494230c` passes 93 tests and nine subtests. Previous revision
`c8d9a00` completed green required CI. All 164 execution contracts remain declared; completion remains gated on installed
and live actions, response semantics, fixture cleanup and complete application workflows.

The latest full pass reached 23 receipts, twenty passing and three failed CDN workloads: multi-client, sustained monitor
and nested maximum load. Those failures remain evidence. Source baseline completion passed installed with 200 finished
requests, measured concurrency/connection reuse and valid app content. Dynamic query/encoding and non-GET bypass
passed installed. Sustained monitor now has a duration/content/cache/completion adapter with focused installed retry
pending; multi-client and nested maximum-load repairs remain open.

Origin recovery source `f27c98eb73dc2edb5f9c05983fe4cb28d42898de` passes 41 tests and 68 subtests. Installed recovery
ownership/readiness passed using pinned running-container labels and exact Compose project/service/working-directory
identity, instead of inspecting an old image object no longer in the Docker cache. The earlier failed ownership probe is
retained. Full immutable origin installation and clean rebuild acceptance remain open.

## Sustained completion and recovery receipts

Focused installed sustained-cache qualification at generator revision `cd8dfcb4c50d21dc5d32529bdf7259d51494230c`
passed 300 requests, declared duration, all six application/cache samples, actual concurrency, connection reuse and
cleanup, with zero transport failures or cancellations. Earlier wrk cutoff and missing-content runs remain failures.
Continuous traffic is restarting on this immutable candidate. Source validation passes 93 tests and nine subtests.

Origin recovery query and running-container provenance repair passed installed ownership/readiness. It requires the
pinned base label, application label, exact container name, Compose project/service and working directory. Unknown
provenance still fails. Origin source validation passes 41 tests and 68 subtests. Immutable full origin installation,
complete workflows and clean rebuild acceptance remain open.

The most recent interrupted full pass had 23 receipts, twenty passing and three failed multi-client/sustained/nested
maximum workloads. Every failed/interrupted pass remains failed. Full two-pass catalog acceptance, scanner semantics,
fixture restoration, nested attribution, rendered completeness, merged-artifact delivery, clean rebuild, sustained-rate
and repeat-apply qualification remain outstanding.

## Multi-client repair qualification

Generator source `50d3ce4ff13e1a97fce76d86861085b81a7ba05f` passes 94 tests and nine subtests, mypy, Pylint,
Ruff and full pre-commit. All 164 source execution contracts remain present. Multi-client source now runs twenty isolated
synthetic clients, each completing five requests, and checks its own returned cookie, True-Client-IP and Fastly-Client-IP.
WAAP sanitizes client-supplied X-Forwarded-For; request dispatch and received forwarding semantics are distinguished.
Installed multi-client qualification is pending. Earlier regex, missing-content, worker and cancellation failures remain
failed evidence. Nested stress attribution and fixture restoration remain open.

Focused installed multi-client qualification passed all 100 requests across twenty clients, each with five identity/cookie
assertions and closed connections. No transport failures or cancellations occurred. This qualifies the bounded identity
adapter; broader nested stress, fixture restoration, rendered completeness and final full-catalog acceptance remain open.
Continuous traffic is restarting on `50d3ce4ff13e1a97fce76d86861085b81a7ba05f`.

## DVGA replica consistency repair

The native browser verifier passed six checks on each of all four replicas, including native paste submission,
subscription delivery and scoped fixture removal. Published HTTP and HTTPS runs exposed unstable replica selection:
three runs missed subscription updates and all four failed cleanup. Those outcomes remain failed evidence.
The four exact synthetic paste objects left by those runs were recovered through native replica requests with title,
content and ID ownership assertions, confirmed removal and a separate private recovery receipt. No failed receipt changed.

The current origin candidate binds browser, GraphQL and WebSocket requests to a replica cookie and retains a private
fixture journal for recovery. Source checks pass 57 tests, type checking and changed-file repository hooks.
Immutable installation and published-layer retry are in progress. Complete catalog and final deployment gates remain open.

## Published DVGA workflow qualification

Origin `a2409bdcc4b6b77d7ada4b32fef22d61fde01306` passed the six-check browser workflow on both domains
over HTTP and HTTPS, including actual subscription delivery and scoped fixture removal. Fifty-four screenshots from
native replicas, origin nginx and published layers were reviewed as a contact sheet, with a full-size form review.
Earlier inconsistent-affinity runs remain failed. This qualifies the declared paste/subscription slice, not all DVGA
features, full scenario scope, or final fresh-deployment acceptance.

The next CSD candidate derives native and published routes and scopes clear-log requests carrying a synthetic fixture
ID to that run while preserving other entries. Source checks pass 58 tests and type checking; installed browser checks
are pending. CSD protection remains disabled. All T01-T16 completion gates remain open.

## CSD browser synchronization repair

The CSD immutable verifier passed five checks through origin nginx with fixture restoration. Concurrent native and
published checks retained fixture-baseline failures, and published checks retained checkout-script cancellation failures.
The verifier now bounds waits, synchronizes the receiver counter, checks the clear response against real receiver state,
and finishes checkout resources before navigation. It retains a private fixture identity journal for interrupted recovery.
Sequential same-source native and published retries remain pending; no failed run was relabeled.

## Sequential CSD workflow qualification

Origin `379fabe55afe057d84ce80f82a82eb4bab551fbc` passed five browser checks on all four native replicas
and both domains over HTTP and HTTPS. Every run verified receiver identity, counter, actual checkout submission,
dashboard, native scoped-clear action and preservation of the pre-existing receiver entries. Earlier overlapping,
resource-cancellation and interrupted runs remain failed evidence. Screenshot contact sheets and a full-size dashboard crop were reviewed; the dashboard renders existing synthetic entries.
Continuous traffic restart is in progress. Complete application/catalog and Terraform acceptance remain open.

## Readiness fixture cleanup

Screenshot review exposed repeated CSD readiness receiver entries. The readiness source now sends a unique fixture ID,
clears only that probe in a finally block and requires its absence. A failing regression reproduced the missing cleanup;
59 source tests and repository hooks now pass. Installed repeated-readiness qualification is pending. Historical
receiver data stays preserved; complete repeat-install and clean-rebuild acceptance remain open.

Installed origin `ea66d4bddc418a3204f24a6488aa865333092f48` passed two consecutive readiness reruns.
Both exited zero and retained the receiver count at 227, confirming the scoped probe leaves no new entry.
The first controller invocation used an unsupported positional argument and remains a failed tool receipt.
This focused idempotence proof does not complete all fixture reruns or final Terraform convergence.

## crAPI published image qualification

The published five-view crAPI verifier passed on the API HTTP domain but failed premature shop image assertions
on the other three layers, while refresh and all view identities passed without browser transport errors. Those runs
remain failed. The source now waits for pending requests and completed image loading before asserting image dimensions.
Pinned immutable installation and fresh published retry are pending. Signup, workshop, MailHog and complete fixture
restoration remain open. Origin readiness repair CI passed all required checks at `ea66d4b`.

Origin `f7ddb6d4bdf9566a9d00ff7266281e7b9bd198e1` passed the crAPI five-view browser verifier on both
domains over HTTP and HTTPS. Every seeded view, shop image and deep-link refresh assertion passed without browser
errors or transport failures. Earlier premature-image assertions remain failed evidence. Signup, additional workshop
workflows, MailHog rendering, comprehensive fixture restoration and final merged/fresh deployment remain open.
Continuous traffic is enabled and running; the current pass has one accepted receipt so far.

## RESTaurant rendered role workflows

The reusable browser verifier executes Swagger OAuth password authentication and actual authenticated GET profile
requests for both seeded customer and chef roles. Those four checks passed live. ReDoc rendered but failed its local
asset assertion because FastAPI still added a Google Fonts style sheet. The adapter now disables external font loading;
60 source tests, type checking and repository hooks pass. Immutable installed verification remains pending while the
active rapid-browsing catalog scenario finishes. No ReDoc or full RESTaurant acceptance is claimed yet.

Rapid browsing remains in progress on installed generator `506d542`: 216 persisted action records include 17 failed
rendered assertions. A source regression also exposed stale 403 evidence incorrectly reused for SPA fragment routes.
Generator `96f2fad` rejects that stale success and performs a fresh navigation when the previous document was blocked.
Seven focused Node tests and repository hooks pass; candidate CI and installed qualification remain pending.
The active older-source run remains untouched for its terminal receipt.

The older-source rapid browser completed all 360 action records and closed Chromium: 111 rendered, 208 mitigation
candidates and 41 failed actions. The result remains failed, including stale-mitigation evidence. No complete catalog
pass is accepted. The next immutable generator has green required CI and rejects stale blocked SPA evidence.
HTTPBin source now derives native assets, specification and form routes from the request prefix; 61 origin source tests
and type checking pass. Its browser verifier requires actual form submit and returned synthetic field values.
Installed qualification is pending after the completed rapid run.

## HTTPBin published form schema repair

The owned API-definition saved plan updated one existing resource and applied successfully. Twelve JSON control
responses passed: valid synthetic JSON returned 200 and missing/wrong demo IDs returned 403 on both domains over
HTTP and HTTPS. Native form submissions still failed. Attributed API-security events identified omitted optional
form fields as non-nullable, so the form schema now explicitly permits empty values while retaining the JSON contract.
A new exact schema upload, ownership-checked plan, apply and published browser retry are in progress. First plan/input
failure and all failed form runs remain preserved. No control or final Terraform convergence acceptance is claimed.

## HTTPBin form acceptance after attributed repair

The corrected nullable form schema applied through a saved ownership-checked plan updating one API definition.
The HTTPBin four-check browser verifier then passed on both domains over HTTP and HTTPS, including actual
form submission and echoed fields, local Swagger assets and the correct specification prefix. All twelve JSON
control cases remained valid: the correct demo ID returned 200, missing/wrong IDs returned 403. Attributed event
evidence identified optional-field nullability in the earlier failure. Those failures and the ambiguous-name upload
remain preserved. Full control attribution and final unchanged Terraform apply remain open.

RESTaurant passed all five rendered role/docs checks on both published domains over HTTP and HTTPS. Native
replica verification and screenshot review are in progress. Continuous traffic is active on `96f2fad`; the current
full catalog pass remains incomplete.

RESTaurant native browser checks exposed 404 at the advertised prefix on every replica despite successful root
responses and generated prefixed documentation. The pinned ASGI adapter now strips only the declared prefix for native
requests. Source checks pass 62 tests and repository hooks. Immutable installation and native/published reruns are
in progress. The earlier native failures remain failed evidence; the catalog pass interrupted for installation remains
incomplete with thirteen accepted receipts.

Origin `f4c8d2f` passed all five RESTaurant browser checks on every native replica. Published reruns retained
intermittent 403 blocks on documentation assets and login, while the HTTPS www layer passed. These are failed
serving-layer evidence and require control attribution; the native prefix adapter does not establish published
acceptance. Continuous traffic restart is in progress.

RESTaurant native replicas and both HTTPS domains passed the five-check workflow after the prefix repair.
Intermittent HTTP failures remain preserved; a fresh synthetic actor live diagnostic passed the www HTTP workflow.
The verifier now assigns a unique opaque actor per run for independent attribution. Immutable installed qualification
for this last verifier change remains pending. No current control attribution was inferred from the transient block.

Generator `808cd6b` adds a second regression distinguishing fresh blocked document probes from stale SPA fragment
evidence; all eight focused Node checks and repository hooks pass. Origin `2e51126` assigns a fresh synthetic
RESTaurant actor per verifier run. Both immutable installs and next installed qualifications are in progress.
All 164 catalog entries remain, and two complete accepted catalog passes are still outstanding.

Installed origin `2e51126` passed the fresh-actor RESTaurant five-check browser workflow on both HTTP domains.
HTTPS rechecks and the focused rapid-browsing retry continue. Required origin CI is green. Complete workflow,
mutation restoration, scanner scope, fresh deployment and final catalog acceptance remain open.

Expanded crAPI mechanic navigation rendered its service form but exposed a root image URL escape on return.
The immutable frontend adapter now anchors vehicle image URLs under the crAPI base and fails if its pinned upstream
source changes. Source checks pass 63 tests and repository hooks. Installed qualification remains pending.
The focused rapid retry has fourteen failures among 216 persisted actions; blank HTTP 200 SPA documents remain
failed despite corrected fresh-versus-stale mitigation handling. The run continues for a terminal receipt.

The focused rapid retry completed 360 records and closed Chromium on generator `808cd6b`, but failed with
54 action failures, unmatched server failures and six cancellations. It remains failed; controller exit zero did
not establish scenario acceptance. Private receipt: `resume-focused-rapid-fresh/pass-focused-1791030621163638487/receipt.json`.
Origin `62d25ed` passed immutable installation and the expanded seven-check crAPI verifier through origin nginx,
including mechanic form navigation and vehicle image return. Published verification is in progress.

The expanded seven-check crAPI workflow passed through origin nginx and both HTTP domains. HTTPS rendered all
seven views but failed a mixed-content redirect at the mechanic list endpoint. The frontend adapter now requests the
canonical trailing-slash endpoint directly, matching native Django routing. Source checks pass 64 tests and repository
hooks; immutable rebuild and HTTPS retry remain pending. Those mixed-content failures remain failed evidence.

Rapid failure records now distinguish attempted from performed actions and retain private response size, script count
and body-character count for failed navigation. Eight focused Node tests and repository hooks pass. Source `3722a58`
is pushed; immutable installed qualification is pending. This diagnostic change does not accept the earlier failed run.

Origin `c55a6ec` passed the expanded seven-check crAPI verifier on both domains over HTTP and HTTPS after the
canonical mechanic endpoint repair. All views, mechanic form, vehicle image return and deep-link refresh checks passed
without browser errors or transport failures. Signup, service-request mutation workflows, MailHog rendering and
comprehensive fixture recovery remain incomplete; this slice does not establish full crAPI acceptance.

Native Juice Shop browser verification failed all four replicas: published frontend API paths returned SPA HTML
with HTTP 200 instead of product JSON. Source adapter now strips the application prefix before native request and
WebSocket dispatch while preserving origin nginx routing and framing repairs. Source checks pass 65 tests and hooks;
immutable installation and native browser retry remain pending. Earlier native failures remain failed evidence.

The next Juice Shop native retry still failed because existing processes retained the old bind-mounted preload inode.
A source configuration digest label now changes the Compose service declaration whenever the preload changes, forcing
container recreation through immutable provisioning. Source checks pass 66 tests and hooks. Installed recreation
and native browser acceptance remain pending; staged file presence was not treated as running-source acceptance.

Origin `e536986` passed immutable installation; the prefixed native Juice Shop product API now returns product JSON.
All four native replicas passed all ten browser checks after adapter-triggered recreation, including products,
images, login, basket, supporting pages and Socket.IO frames. Published rechecks continue.
Continuous traffic restart is in progress. No full catalog or clean deployment acceptance is claimed.

Origin `e536986` passed all ten Juice Shop browser checks on all four native replicas and both domains over HTTP
and HTTPS. Published checks reverified images, login, basket, supporting routes and Socket.IO after container recreation.
The workflow aggregate now additionally reconciles actual HTTP assertions against every manifest workflow and reports
missing assertions; supported HTTP slices remain distinct from complete declared-workflow acceptance.

Installed origin `f99a17f` passed all 33 supported native HTTP checks and correctly reported declared-workflow
acceptance false with explicit missing-workflow lists. Separate browser slices remain evidence requiring a combined
source/layer receipt; the HTTP report alone cannot establish complete coverage.

A reusable combined matrix is being added to join source-pinned browser assertions and HTTP checks across every
native replica, origin nginx and four published layers. Foreign source, layer, failed runtime and missing-replica
regressions pass. Missing declared workflows remain explicit, and screenshot/manual fixture acceptance remains
separate. The matrix is not yet installed or accepted.

The combined receipt matrix now requires matching source/archive digests and explicit browser kind/base, successful
runtime cleanup, no browser errors and every required per-workflow check. It rejects foreign sources, wrong layers
and missing replicas. The installed browser runtime now records kind and base. Source checks pass 69 tests, mypy,
Pylint and repository hooks. Whoami proxy checks additionally require actual received forwarding headers; native
diagnostics remain separate. Immutable combined-matrix installation and execution are pending.

The active rapid catalog scenario now retains thirteen failed records among 264 persisted actions; it remains
incomplete. Failure details show a successful SPA document with a blocked supporting product request, so each
fragment route will now dispatch from a fresh document. Source regression checks pass; installed retry is pending.
Browser runtime and matrix receipts additionally require an exact verifier digest.

Current combined-matrix source passes 69 Python tests, type checking and repository-configured Pylint. Its browser
evidence must match the installed verifier file digest as well as source/archive, kind and serving layer. The active
older-source rapid scenario has 336 persisted actions and 25 failures; it remains failed/incomplete while finishing.
Next source-pinned matrix installation and run remain pending.

The latest origin CI failed Python type/lint checks after the combined-matrix change despite focused source checks.
The required CI repair loop is active; no merge or complete acceptance is claimed. Rapid failure resource records
are now scoped to their own route rather than inherited from previous routes.

Origin CI findings were repaired: renderer complexity was split into its own adapter binding helper and receipt
test fixtures now have explicit types. All nineteen Python files pass mypy and repository Pylint, 69 tests pass,
and repository hooks pass. Required CI is pending. The older-source rapid run completed 360 records but retained
46 failures; it remains failed, including requests interrupted at its deadline.

The combined application matrix is now running on digest-verified origin `a23d46e`, using freshly exported
synthetic fixtures and sequential browser checks across native replicas, origin nginx and both HTTP/HTTPS domains.
Continuous traffic restart is in progress on generator `92b5d26`. Source checks remain separate from matrix acceptance.
The most recent completed rapid pass retained 46 failed actions and stays failed evidence.

Current origin candidate `a23d46e` passed required CI. The consolidated installed matrix passed all supported
HTTP checks on every native replica, origin nginx and both domains over HTTP and HTTPS; its first four browser
receipts passed. The run remains in progress with declared-workflow and screenshot gates open.

The current consolidated matrix has passed all HTTP layers and 26 browser receipts without a browser failure so far.
Continuous traffic remains active. The matrix is not complete; source/layer assertion reconciliation and manual
screenshot review remain required, with signup and fixture recovery still explicit gaps.

The consolidated matrix has 35 passing browser receipts so far after all HTTP layers passed. Continuous catalog
traffic is enabled and active on `92b5d26`, currently at rapid browsing with thirteen earlier accepted scenario
receipts. No terminal complete catalog or matrix acceptance is claimed.

The consolidated matrix reached 51 passing browser receipts with no browser failure so far. Fresh-document rapid
browsing has one failed action among 48 persisted records; it remains incomplete. Current generator required CI
is green. No full catalog or matrix acceptance is inferred from this progress.

The consolidated matrix completed with 60 browser runs and failed complete acceptance. Native crAPI had prefixed
asset 404s; other browser receipts passed. The exact missing workflow list and private source-bound matrix receipt
remain preserved. A pinned native frontend nginx prefix repair passes 70 source tests and awaits immutable installation.
The concurrent fresh-document rapid run has six failed actions among 144 persisted records and remains incomplete.

The completed combined matrix explicitly missed native whoami header echo, CSD replica state and crAPI signup/native
frontend routing. The next verifier adds actual supplied-header echo on native whoami and one tagged CSD receiver
mutation read through every layer, followed by scoped removal and preservation of unrelated entries. Regression
checks pass 71 tests and type checking. Native crAPI frontend prefix repair is also source-complete; installed
qualification remains pending.

The fresh-document rapid catalog run completed all 360 records: 86 rendered, 250 mitigation candidates and 24
failed actions. It remains failed acceptance. The next application verifier includes native whoami header echo,
CSD shared-state mutation/recovery, native crAPI prefix dispatch and journaled synthetic signup/MailHog verification.
Signup cleanup uses quoted psql variables and exact synthetic account identity; installed qualification is pending.

First installed signup verifier invocation failed before launch because its parser choice was missing. The source
CLI now declares the signup kind and has a parser regression; 74 tests pass. No account was created by that failed
invocation. Immutable reinstall and actual signup/recovery qualification remain pending.

Corrected signup CLI immutable installation passed. The expanded crAPI seven-check workflow through origin nginx
passed again, while actual signup/MailHog/recovery verification remains running. Native frontend routing and
CSD/whoami gaps need same-source installed requalification before complete acceptance.

The first actual signup run stalled and was stopped through exact verifier ownership. Its runtime receipt remains
failed, and the account was removed, but welcome vehicle/mail ownership was not yet identified. Recovery now
discovers the exact synthetic recipient mail, extracts its VIN, and verifies mail removal, retaining incomplete
recovery as failure. Bounded signup waits and private recovery requalification are in progress.

MailHog welcome-body discovery required raw MIME decoding: its v2 list content body was empty while raw SMTP
content retained the quoted-printable VIN. Recovery now parses that raw message and accepts its actual message-ID
format, with confirmed removal. The second signup run also stalled on browser response completion and remains
failed. The next verifier bounds response-body reads; installed recovery and signup retry remain pending.

Separate recovery receipts passed for both interrupted signup runs, removing their exact synthetic account, welcome
vehicle and MailHog message. Original failed receipts remain unchanged. The bounded signup retry failed explicitly
on response-body completion; response framing and native UI outcome are being investigated.

Signup diagnostics confirmed the native UI success text is "User Registered Successfully!", while the verifier
expected backend wording. The browser now verifies that actual rendered success and welcome-mail identity instead
of relying on a browser response-body read not consumed by the upstream success path. Earlier timeout runs remain
failed; synthetic diagnostic fixtures are being recovered and final installed signup qualification remains pending.

The installed signup completion-aware run rendered success but failed because the upstream frontend returned a
Response without consuming its body. Its exact account, vehicle and mail cleanup passed. The immutable frontend
adapter now consumes the JSON success response before signalling UI completion. Source regression and rebuild
qualification are in progress; the failed run remains failed evidence.

The combined matrix now includes signup and MailHog assertions only after exact source/layer/browser success
and passing synthetic account/vehicle/mail recovery. A false-recovery regression fails; source checks pass 76 tests
and hooks. Immutable response-consumption frontend rebuild and actual signup qualification are still in progress.

The response-consumption frontend installed successfully. Signup request completion, rendered success, welcome mail
and scoped account/vehicle/mail recovery passed; the browser slice still failed on MailHog GET /api/v2/jim 404.
The same endpoint returns 404 on the direct MailHog replica, so intentional disabled-feature semantics are being
checked against the pinned runtime. No arbitrary 404 is accepted.

Pinned MailHog help and container arguments prove Jim is disabled: its chaos-monkey opt-in flag is absent and
GET /api/v2/jim returns 404 natively. The signup verifier now declares only that exact 404 as the expected disabled
feature outcome; other MailHog errors still fail. Signup request completion, UI success and recovery already passed
separately; immutable expected-outcome retry remains pending.

Origin `6551549` passed installed signup verification through origin nginx: native submit, completed request,
rendered success, welcome MailHog message and confirmed scoped recovery all passed. The exact disabled Jim 404
was recorded as an expected negative. Published signup checks and the next consolidated matrix are running;
continuous traffic restart is in progress. No complete application or catalog acceptance is claimed yet.

Installed origin `6551549` passed signup, request completion, rendered success, welcome-MailHog checks and scoped
recovery on both domains over HTTP and HTTPS. The next consolidated matrix includes native frontend routing,
whoami supplied-header echo, CSD cross-replica state and recovery-gated signup. It is running; no final matrix
or fresh-deployment acceptance is claimed.

ZAP status parsing now rejects malformed/missing numeric status and fails unfinished spider/passive/active phases.
Partial scan reports remain partial evidence. The status-parser regressions and shell checks pass; immutable scanner
qualification remains pending. The consolidated application rerun has 41 passing browser receipts so far.

The current matrix rerun has 55 browser receipts with zero browser failures, including repaired native crAPI
frontend routing. Signup and final source/layer reconciliation remain running. ZAP active scanning now records
its actual per-application scan IDs and terminal completion separately from spider requests; installed scanner
and full-catalog acceptance remain pending.

The application matrix has 61 passing browser receipts so far, including completed signup with scoped recovery.
Active scanner acceptance now requires matching per-application scan IDs and terminal status records; startup or
spider requests cannot satisfy the active phase. Missing/foreign/incomplete scanner regressions pass.

## Complete declared application matrix

Origin `6551549` completed the consolidated source-bound matrix with no missing declared workflows and 66 passing
browser receipts across every native replica, origin nginx and both domains over HTTP and HTTPS. Signup recovery,
CSD shared replica state and native header echoes passed. Private matrix: `private-browser-matrix-1791038863474345797`.
The matrix retains accepted=false pending screenshot review and comprehensive fixture-recovery/fresh-deployment
acceptance. Two full accepted catalog passes and the clean Terraform lifecycle remain outstanding.

Manual review of all 315 matrix screenshots found that some Juice Shop score-board captures remained at a loading
spinner despite passing heading assertions. Rendered acceptance is therefore still open. The verifier now requires
visible challenge cards and spinner removal, and signup screenshots wait for modal animation. The matrix automated
pass stays provisional; screenshots were not accepted as complete.

The stricter score-board verifier at origin `7b96647` passed all ten browser checks on every native Juice Shop
replica and both domains over HTTP and HTTPS, requiring visible challenge cards and no loading spinner.
Screenshot review of the corrected score-board is in progress. The earlier automated matrix pass remains
provisional until corrected rendered evidence and comprehensive fixture/fresh-deployment gates pass.

The corrected loaded Juice Shop score-board screenshot was manually reviewed at full size and shows populated
challenge cards and counters. The active catalog pass has seventeen receipts, sixteen accepted and failed rapid
browsing. That failure remains; its timeout/cancellation is not mitigation acceptance.

Generator `be35a22` passes required CI and 128 source tests plus nine subtests with runtime dependencies.
The active pass retained rapid-browsing failure and was stopped for focused scanner qualification. Immutable
scanner candidate installation passed; ZAP baseline/active completion verification is now running through the shared
budget. No scanner or full catalog acceptance is claimed from source contracts alone.

Focused installed ZAP baseline dispatched each declared target but failed incomplete spidering. The failed
receipt remains failed. The aggregate verifier now also requires a launched terminal outcome before keeping
dispatch acceptance true; a failed scanner cannot retain aggregate acceptance just because its GETs dispatched.
Active ZAP qualification is still running.

Focused installed ZAP active scanning passed per-application phase completion and intended dispatch with 2,459
attributed requests, 2,226 mitigation candidates, no transport failures and no cancellations. ZAP baseline remained
failed because spidering did not complete. Private receipt: `resume-focused-zap-completion/pass-focused-1791040551262201274/receipt.json`.
Continuous traffic restart is in progress; complete scanner semantics and final catalog acceptance remain open.

Focused ZAP baseline qualification passed on generator `e0abbc2` with all six intended target dispatches,
105 attributed HTTP requests, completed native spider/passive phases, no transport failures and no cancellations.
Private receipt: `resume-focused-zap-baseline-final/pass-focused-1791041121612358575/receipt.json`. Earlier
incomplete baseline remains failed. Pinned runtime option names were verified and update/telemetry flags corrected;
next immutable scanner rerun is pending.

Scanner continuation: generator `6e854c3` completed focused baseline and active phases with 105 and 743
attributed requests, zero transport failures and zero cancellations. Silent startup suppressed unsolicited update
requests; private receipt: `resume-focused-zap-completion/pass-focused-1791041915359446641/receipt.json`.
This remains phase qualification only: generator `f0bfeaa` now requires distinct native active-scan message IDs
per application, and its installed qualification is pending. Source verification passed 132 Python tests and
9 subtests. The complete application matrix on origin `7b96647` is running; final coverage remains open.

The full workflow matrix on origin `7b96647` completed with no missing workflow/layer entries and 66 browser
receipts. Private receipt: `private-browser-matrix-1791041664563406805/matrix-receipt.json`. Review of all
315 screenshots found a DVGA capture-order gap: the initial public-paste screenshot preceded seeded content
loading, although later persistence and subscription screenshots showed the data. Origin `695c07c` moves the
seeded-content wait before that capture; installed same-source matrix qualification remains required.
Generator `f0bfeaa` passed the stronger native active-message gate for all five declared scanner targets,
with 105 baseline and 743 active requests, zero transport failures and zero cancellations. Private receipt:
`resume-focused-zap-completion/pass-focused-1791042466568314551/receipt.json`. Complete catalog, broad fixture
restoration, merged installation and fresh deployment gates remain open.

Continuation receipts: origin `695c07c` completed the matrix with 66 browser receipts and no missing
workflow/layer entries (`private-browser-matrix-1791042851771534564/matrix-receipt.json`). Screenshot review
confirmed populated DVGA pastes but exposed Juice Shop image capture timing; origin `b30656c` requires visible
images to load before capture. Lazy-image and wrong-content/broken-image browser regressions passed; origin
source passed 76 tests and 69 subtests. Origin/API HTTP and both HTTPS published landing crawls passed on the
previous candidate; HTTP-www retained its lazy-image failure. Same-source final reruns remain required.

Generator `f0bfeaa` completed rapid browsing with 360 records: 78 rendered, 257 mitigated and 25 failed; this is
a failed scenario. Private security events attribute blocked supporting assets to Malicious User Mitigation.
The API-fuzz scenario failed with 31 cancellations and a timed-out raw CONNECT, suppressing subsequent method
launches. Generator `2e30e63` preserves forwarded CONNECT attribution, permits paced client completion, rejects
duplicate or undeclared action IDs, and binds each user-agent session to its own run-specific actor. Source
checks passed 135 tests, nine subtests and eight Node tests. Focused installed qualification is pending.

Rate windows preserved both a failed 185.2 RPS measurement and later 197.3 RPS measurements. Benign success
in those windows was 100 percent with zero baseline transport failures; cumulative benign counters include
two HTTP 503 responses. These windows do not establish final sustained fresh-deployment acceptance. WAAP
required CI is green after Python assertion/formatting and Terraform formatting repairs. Full catalog, broad
fixture restoration, merged artifacts, clean rebuild and repeat apply gates remain open.

Latest origin `b30656c` passed all four published landing crawls (28 checks per layer), including HTTP-www
after lazy-image verification repair; the original failed HTTP-www receipt remains failed. Same-source full
workflow matrix and screenshot review are pending. Generator `2e30e63` focused API fuzz dispatched 169 requests
with zero transport failures/cancellations but failed three stale catalog CONNECT requirements; `f980a6e`
corrects all thirteen forwarded-method contracts and passed required CI. Rapid qualification has reached
240 exact actions, 192 rendered and 48 mitigated, with no failed action records yet; it remains incomplete.

Generator `287ebda` adds Nikto nested attribution using the pinned scanner's supported `-config` and USERAGENT
interface while retaining native version/test identifiers and plugin paths. Source checks passed 136 tests and
nine subtests; installed child attribution qualification remains pending. No task is marked complete from these
focused checks.

Origin `b30656c` completed its same-source workflow matrix: 66 passing browser receipts, no missing
workflow/layer entries, and 315 manually reviewed screenshots. Key full-size images showed loaded products,
populated score-board cards, seeded DVGA pastes and rendered ReDoc. Private receipts:
`private-browser-matrix-1791044273150348894/matrix-receipt.json` and `manual-render-review.json`. All five
landing crawls (origin plus both domains over HTTP/HTTPS) passed 28 checks each. Broad fixture restoration
and fresh-deployment acceptance remain open.

Installed `15b27f1` passed API fuzzing with all 169 dispatch/response requirements, seven native tool
invocations, zero transport failures and zero cancellations. Private receipt:
`resume-focused-api-final/pass-focused-1791045397187588237/receipt.json`. Native nested Nikto passed its
child dispatch and tool receipt (`resume-focused-nikto-native/pass-focused-1791045434542675296/nested-web-app-attacks/web-app-attacks--05-nikto-scan/receipt.json`).
The prior rapid run reached 336 successful rendered/mitigated action records but timed out before the final
user-agent session, leaving 24 required actions absent. That run remains failed. `15b27f1` reduces only idle
settling time after pending requests finish; installed full rapid/catalog qualification remains open.
Continuous restart is in progress. No clean rebuild or final Terraform convergence is claimed.

Fixture exporter idempotence passed two reruns on origin `b30656c`: crAPI user/vehicle/video/order, DVWA user
and RESTaurant user counts and returned object identities stayed stable. Private receipt:
`private-fixture-rerun-1791046618208888465/receipt.json`. Attack mutation recovery remains incomplete.
Generator `1939ebe` binds complete pass receipts to exact scenario IDs/source/archive digests and passed
138 tests with nine subtests and repository Pylint. WAAP acceptance now also requires matching catalog
provenance, the benign rate budget, balanced domains and all nine application paths; its full pytest run passed
333 tests and 396 subtests with one environment skip. Generator `43e7f73` records document commit before
render checks and extends per-page/drain waits while retaining the 900-second scenario deadline. Installed
qualification is pending. The current older pass retains its API-denial timeout failure and rapid failures.

The three application manifest copies match byte-for-byte at SHA-256
`a0f63e1e5c2361e70b6af46efa42ffe9eebc95ab93258d421da796bdaae4067b`, declaring nine applications
and 33 native serving ports. Traffic source drift was reconciled with current default-branch CSD cleanup and
immutable CloudWatch changes; source checks passed after the merge. Generator `d32363b` is the next immutable
source candidate. Installed focused qualification remains on `43e7f73`: API denial passed three HTTP 403
responses and one allowed HTTP 200 control, and rapid qualification is incomplete. Earlier failures remain failed.

Focused generator `43e7f73` completed all 360 rapid action records but remained failed: 310 rendered,
48 mitigated and two resource-drain failures, with twenty cancellations. Both failed route diagnostics
contained an external VT323 font transport failure. Private receipt:
`resume-focused-deny-rapid/pass-focused-1791047207784715965/receipt.json`. API denial in that run passed.
Origin `1392e22` packages the licensed VT323 font locally under the Juice Shop application route with
idempotent HTML adaptation; 77 source tests and 69 subtests pass. Immutable installation and focused
render/traffic qualification are pending. The next traffic candidate `e52a996` retains pending-request
diagnostics and includes merged default-branch repairs. Complete coverage and clean rebuild remain open.

Local font delivery passed native/origin/published live byte checks on origin `c74a0bd`: 153,116-byte
VT323 asset at SHA-256 `cf4de751ada78ceac033dbe16a687742939995b77bc2a052ae17a4957958594d`;
HTML contains the local font declaration and no external Google Fonts links. The earlier `1392e22` font
probe returned SPA HTML and remains failed. Source regression now binds the real native frontend asset
root. The concurrent prior matrix crossed an origin update and cannot qualify same-source acceptance;
a fresh matrix and published crawls are running. Traffic remains in focused qualification and must be
restarted afterward.

Origin `c74a0bd` passed ten Juice Shop browser checks on all four native replicas and both published
domains over HTTP and HTTPS after the local font repair. Current full matrix/crawls are running. Generator
`e52a996` rapid qualification overlapped that origin reinstall and retained one HTTP 503 and two HTTP 502
failures; that run cannot establish acceptance. It must finish as failed, followed by a stable-origin rerun.
Origin `9347439` adds end-of-run installer-provenance comparison to reject matrix source drift.

The overlapping rapid run completed with 360 records (309 rendered, 48 mitigated, three failed) and seven
cancellations. Private receipt: `resume-focused-rapid-fresh/pass-focused-1791048417035287680/receipt.json`.
One HTTP 503 and two HTTP 502 responses during origin replacement remain failures. A stable-origin rapid
rerun is now in progress with no further origin mutation. Current origin source `9347439` required CI is green;
installed application source remains `c74a0bd` during matrix qualification.

Origin `c74a0bd` completed a stable full workflow matrix with 66 passing browser receipts and no missing
workflow/layer entries (`private-browser-matrix-1791048776842279571/matrix-receipt.json`); screenshots are
being reviewed. Generator `be578b6` records explicit navigation/closing phases and permits only dispatched
Socket.IO polling-session cleanup in those phases; asset cancellation and execution-phase failure still fail.
The previous verifier recorded those deliberate long-poll closures as generic transport errors. Source checks
pass 139 tests and nine subtests; current installed rapid rerun remains on `e52a996` and is incomplete.

Stable-origin rapid rerun on generator `e52a996` completed all 360 declared actions: 312 rendered and
48 mitigated, zero failed action records. Its terminal receipt still failed seven Socket.IO cleanup
cancellations (`resume-focused-rapid-fresh/pass-focused-1791049371449327802/receipt.json`). Generator
`b40132d` includes scoped navigation/closing cleanup classification and passed required CI; installed
qualification is pending. The previous receipt remains failed. Local-font matrix `c74a0bd` screenshots
were manually reviewed and retained with final acceptance false because broader gates remain open.

Installed rapid qualification passed on generator `b40132d`: all 360 actions, 312 rendered and 48
mitigated, zero failed action records, zero transport failures and zero tool cancellations. Private receipt:
`resume-focused-rapid-fresh/pass-focused-1791050358547096263/receipt.json`. Earlier failed receipts retain
their original outcomes. Continuous traffic restart is in progress; two full catalog passes remain required.

Source-stability matrix `9347439` passed with all 66 browser receipts and no missing workflow/layer
entries (`private-browser-matrix-1791050358484229414/matrix-receipt.json`). Continuous traffic is enabled
and active on `b40132d`; six early catalog receipts pass. Full pass acceptance remains pending, and no
clean rebuild, broad mutation-restoration acceptance or unchanged repeat apply is claimed.

Generator `86a8d42` adds scoped synthetic RESTaurant role mutation journaling/restoration and current
profile role verification; 141 source tests and nine subtests pass, but installed qualification is pending.
Continuous service remains on accepted focused candidate `b40132d` without interrupting the full pass.
The source-stability matrix screenshot review on origin `9347439` is recorded with final acceptance false
while mutation/scanner/connection, full-catalog and clean-deployment gates remain open.

The continuous pass on `b40132d` reached forty scenario receipts and retained failures in Kraken, origin
torture and crAPI. Native wrk logs show threads exceeded configured connections; source `3e31b94` fixes
that constraint. Herd source `cadc2ab` now retains native reports and fails incomplete requests/errors.
crAPI source `b8ec277` fixes decimal OTP generation, the invalid mechanic fallback path and mitigation
classification for coupon probes. Source checks pass 141 tests and nine subtests; installed qualification
is pending. Registration/OTP fixture semantics, video lifecycle and broad mutation restoration remain open.
These failed passes remain failed and cannot establish final coverage. Continuous traffic remains running.
