# Origin and traffic remediation tasks

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>

Implementation issues: [origin-server](https://github.com/f5-sales-demo/origin-server/issues/710), [traffic-generator](https://github.com/f5-sales-demo/traffic-generator/issues/711).

Detailed operational receipts remain in the private lifecycle state directory. Baseline failures are immutable evidence and are not acceptance. Completion requires source, installed, and live checks; all incomplete tasks remain open. Preserve shared DNS, namespace identity, private state, schema fixtures and unrelated worktrees. CSD remains disabled.

## Current acceptance status

All T01–T16 tasks remain open pending their complete source, merged-installation and live acceptance.
Current source/installed origin is `dc99bef`; generator is `6529de0`. WAAP pins immutable archives and
installers. Provider 13.0.3 is the latest checked release, with installed binary/source provenance tied
to enriched API specs v10.0.0. Both Terraform roots validate; the live saved plan succeeds but proposes
two VM replacements that remain unapplied.

Current origin `dc99bef` qualification passed the full declared matrix: 66 browser receipts, complete true,
no missing workflow/layer checks or browser failures, and 315 retained screenshots. Eight application
contact sheets and full dashboard/ReDoc/community views were manually reviewed. Private matrix:
`private-browser-matrix-1791082428479897763/`; review: `manual-render-review-dc99bef.json`.
Final verification on the merged clean deployment remains required.

Two explicit native functional contracts are implemented and passed on both WAAP domains: DVWA
credential stuffing verifies one seeded login, fourteen native rejections and logout cleanup per domain;
crAPI community exposure verifies populated native objects and synthetic author.email values. The accepted
private receipt is `resume-native-functional-both-domains/pass-focused-1791079166467472534/receipt.json`.
All thirty credential POSTs and both community actions were observed with zero transport failures or
cancellations. Failed authentication renewal now raises a prerequisite failure instead of silently
reusing an old token; native valid-invalid-valid crAPI authentication passed. Existing source tests contain
test doubles and are development checks only. Catalog acceptance cannot use dispatch-only receipts.

Eight functional contracts are declared, including three native CSD library execution/cleanup contracts and
measured native slow-header behavior. Seven contracts have live qualification; the command runtime contract remains unqualified. The remaining 156 scenarios lack explicit functional contracts. Five connection scanner scenarios
still use bounded Python probes instead of their named native tools. Costly paced DVGA completion,
broad mutation isolation/restoration and interruption recovery, nested worker semantics, two complete
accepted catalog passes, sustained load/control attribution, merged installation, clean rebuild,
restart/reboot/stop cleanup and unchanged apply/zero-action plan remain open. The full ten-minute native
stress dispatch/report contract passed on the earlier candidate; that does not prove all native stress
features or final functional acceptance.

Required CI passed on generator `5d589b2` and WAAP `f236ff4`; later WAAP tracking/pin CI remains
candidate-specific. Full-head PII enforcement remains failed on twelve localized deployment examples
under the fleet no-locale-refresh policy. Prior generator 48d4b62 required CI passed; current 6529de0 CI is pending. The dc99bef matrix completed with 66 receipts and no missing checks/failures; current manual review passed and continuous traffic is confirmed active/enabled on 6529de0.
CSD remains disabled. Historical failed source, browser, matrix, traffic and CI evidence stays failed.

## Historical candidate evidence

Generator installed/source `8fc528e` passed the stricter crAPI conversion/restoration slice: twelve total
requests, all three updates/three triggers, exact media/name/parameters restored and zero transport failures
or cancellations. All three native JSON HTTP 403 responses match internal-only application rejection and
are classified expected_application_rejection, without attributing WAAP mitigation. Continuous restart is
underway on this exact candidate. Source checks pass 170 tests/nine subtests with one workstation native-tool
skip, plus staged PII and pre-commit. Full catalog, native stress/connection/nested behavior and mutation
isolation remain incomplete.

Installed generator `25a0000` repeats complete conversion/restoration successfully: twelve requests,
zero transport failures/cancellations, exact video restoration, three explicitly identified native application
rejections and two separate mitigation candidates on parameter-update requests. Native 403 conversion
responses are excluded from mitigation totals. Continuous restart is underway on the exact current candidate.
Full catalog/fixture isolation/native stress/final rebuild gates remain open.

Generator source `e8fdee3` repaired required regression mypy typing; complete source mypy passed 74 files
and required CI passed. A source-native wrk repair is now installed through immutable generator `9b1bb1a`: pinned
upstream commit/archive, source-owned drain adapter and binary digests are recorded. It preserves duration,
workers and Lua requests, stops new launches at the deadline and drains dispatched responses within the native
timeout. The delayed native loopback test completed six requests with zero disconnects; full source tests
pass 173 tests/nine subtests with one workstation native-tool skip. Corrupted archive, changed source anchors
and repeat installation have regression gates. Installed paced diagnostic/full stress remain required.
Current origin remains `ecb553e` with complete matrix and manual review; prior native failures stay failed.

Installed drain-enabled native wrk diagnostic on generator `9b1bb1a` finished with zero dispatched
request cancellations, compared with two on the prior native binary. It remains diagnostic-only and recorded
three baseline TimeoutError failures, all DVWA login requests. Private evidence:
`private-native-stage-1791074089980240868/`. Full ten-minute stress is running on the exact installed source
with zero scenario transport failures/cancellations through its third minute; final native completion and
baseline load gates remain pending. DVWA PHP/session behavior is under investigation. Continuous restart
follows the single-boundary stress run. Earlier failed results remain failed.

Origin source `bab591a` moves probabilistic DVWA session expiry out of PHP request workers into a
supervised hourly cleanup of only expired sess_* files after seven days. Native evidence found 591,052
shared session files, intermittent login timeouts and no blocked database queries. Source checks pass
85 tests/69 subtests and staged PII/pre-commit. Installed/live qualification is pending after the active
stress run; preserve sessions and source-specific matrix receipts during update.

Native wrk drain `9b1bb1a` remains clean through nine minutes. ApacheBench duration exit also abandons
in-flight requests; the next source uses native finite request-count baseline workers while full wrk/hey/
Vegeta stress remains ten minutes. All native tool completion/keepalive/response gates remain required.
Earlier cancellation failures are retained; no outcome filter hides dispatched requests.

Full native stress `9b1bb1a` removed all 18 wrk deadline cancellations but remained failed for two
ApacheBench deadline cancellations. Native reports/worker evidence retain that failure. Immutable origin
`bab591a` and generator `235fb9a` are installed: PHP session expiry is supervised outside requests and
ApacheBench baseline uses finite native counts while full stress duration remains ten minutes. Current full
native stress and current-origin matrix are running. The prior complete/manual-reviewed `ecb553e` matrix
remains source-specific evidence; the new origin must pass its own complete/visual matrix. Continuous traffic
restart follows the single-boundary stress run. All final task gates remain open.

Installed DVWA PHP-FPM checks confirm session.gc_probability=0 and session.gc_maxlifetime=604800
on all four replicas; the cleanup timer is enabled. The concurrent native stress retry has zero current
baseline-error receipts through five minutes, versus repeated login timeouts before this source repair.
Finite ApacheBench workers completed native reports with no client cancellations; wrk/hey/Vegeta full
duration and terminal cleanup remain in progress. Current-origin matrix has seventeen passing browser
receipts/no failures so far. Final all-layer/new-source qualification remains pending.

The full ten-minute native stress retry on installed generator `235fb9a` passed its declared dispatch
and native-report contracts: 11,877 scenario requests, all required actions, zero scenario transport failures
and zero client cancellations. Concurrent benign request evidence has zero current transport errors after
the DVWA session-maintenance repair. Private receipt: `resume-focused-kraken-native/` latest pass on
`235fb9a`. Earlier iterations with 20 and two cancellations remain failures. This qualifies the current
contract only; native keepalive reports still show zero reused connections, and full Lua/nested/connection
semantics remain required for complete coverage. Continuous restart is underway.

A fresh continuous startup window on generator `235fb9a` failed the aggregate rate gate at 172.25 RPS
(164.51 benign RPS), despite 100 percent benign success and zero transport errors. Preserve it as failed
rate evidence; a steady-state repeat is running. The current-origin `bab591a` matrix has 63 passing browser
receipts/no failures so far. Source CI passed on current origin and generator candidates. Full catalog,
complete native semantics and final clean/repeat-apply gates remain open.

The complete current-origin `bab591a` matrix passed with 66 browser receipts, zero browser failures
and no missing workflow/layer assertions. Private matrix: `private-browser-matrix-1791074898897738429/`.
Manual screenshot review is pending. A steady-state repeat on generator `235fb9a` reached 197.07 aggregate
RPS, 100 percent benign success and zero baseline transport errors; the earlier startup rate failure remains
failed. Sustained final rate/control/rebuild acceptance is still required.

Manual review of all 315 current `bab591a` screenshots passed through eight contact sheets and four
full-size key pages. The current source has complete native/origin-nginx/HTTP/HTTPS workflow matrix and
manual rendered qualification. Private review: `manual-render-review-bab591a.json`. Complete merged clean
deployment remains required. Scoped costly-DVGA retry on generator `235fb9a` is running; its baseline passed
JSON identity in 40.785 seconds. Earlier expensive-batch timeouts remain failed. Continuous service is stopped
while the focused boundary is occupied and must be restored afterward.

Acceptance policy: every showcase feature and scenario requires real installed/live application and
native-tool behavior. Mocked unit tests, synthetic command shims, replay and dispatch-only receipts cannot
establish functional acceptance. Current full coverage remains incomplete. Native setup, actual payload
action, exact outcome, fixture recovery, source provenance and required serving layers are hard gates.
Any generic connection equivalent remains an explicit gap until its declared native tool behavior is proven.

Current `bab591a` complete matrix/manual review passed all 66 browser receipts and reviewed 315 screenshots.
Private review: `manual-render-review-bab591a.json`. Generator source `72dd8f0` scopes admin-video deletion
to four fresh native uploads owned by a dedicated regular actor; no guessed IDs or shared video mutations
are used. Cleanup requires real native absence checks, including EXIT recovery. Origin `cb08457` seeds the
isolated actor idempotently; immutable installation/export passed. Installed generator/live deletion and
interruption recovery are pending. The new uncommitted mock scenario test was removed at the user request;
acceptance will use the real installed workflow. Existing mock regression checks do not establish acceptance.

Installed native disposable-video run on generator `b3b4edf` passed four fresh uploads/four admin DELETEs
and the declared negative listing case, with 15 scenario requests, zero script failures, zero transport
failures/cancellations and native cleanup evidence. Private receipt:
`resume-focused-disposable-video/pass-focused-1791077206483907610/receipt.json`. Independent native database
checks confirm zero disposable-actor videos and one shared seeded actor video remains. Interruption recovery
and blocked-prerequisite followthrough remain pending. Current pins are origin `cb08457` and generator `b3b4edf`.
The latest scoped costly DVGA run remains timeout with two cancellations despite valid baseline/two/five
responses. It is retained as failed; native video qualification does not override it. Current origin actor
seed revision still needs its own complete rendered matrix. Continuous restart is underway.

## Earlier repair-round observations

Origin source/installed candidate is `d6930ea`; generator source/installed candidate is `695c459`.
The provider release was checked again against the current release API: v13.0.2 remains latest.
The installed provider receipt binds its exact binary/source to enriched API specs v10.0.0.
Terraform replacement plans remain unapplied. No full catalog or clean-rebuild acceptance is claimed.

Generator `58570a3` fixes an unquoted browser navigation wait-state that prevented credential form
submission on `9a514f8`. Executed browser mocks verify all 15 native form submissions, transient setup
retry and failure on a missing form. Source checks pass 158 Python tests/nine subtests, 12 Node tests,
Biome, pre-commit, secrets detection and changed-scope PII enforcement.

The immutable installed build passed the focused credential scenario: 15 intended credential POSTs,
80 total browser requests, zero transport failures and zero tool cancellations. The valid DVWA account
reached the application; the other 14 attempts stayed on the login page. Private receipt:
`resume-focused-credential-final/pass-focused-1791067664607182052/receipt.json`.
The earlier ReferenceError receipt remains failed. This is focused qualification on one HTTPS domain;
all required serving-layer and full-catalog gates remain open. Continuous traffic is active/enabled
on the fixed source; the first observed 4,904 benign requests succeeded. Required generator CI is green.

Origin nginx inspection confirms the 600-second DVGA read timeout and four running replicas with no
DVGA nginx error entries in the inspected log window. A ten-operation origin-nginx probe is running
to distinguish the application/nginx path from the published WAAP timeout; no success is inferred.

The latest full rendered matrix remains origin `3a62623`, with 66 browser receipts and 315 screenshots.
The current origin candidate still needs a new complete matrix and manual review. Complete native stress,
connection behavior, isolated signup/OTP/video deletion fixtures, broad mutation restoration, two full
catalog passes, sustained load/control attribution, cleanup/restart/reboot, merged immutable installation,
one ownership-scoped clean rebuild and unchanged apply/zero-action plan remain required.
All T01–T16 tasks remain open. CSD remains disabled.

Generator `695c459` adds the missing native conversion action after each of three video-parameter
updates. The installed focused receipt confirms all six intended actions, 12 total requests, exact
original video restoration, zero transport failures and zero tool cancellations. All three conversion
responses were JSON HTTP 403; these are observed rejections and do not establish attributed WAAP
mitigation or command execution. Private evidence: `resume-focused-crapi-video-restoration/`.
Source tests pass 159 Python tests/nine subtests and required pre-commit hooks.

Required PII enforcement remains failed: changed catalog scope reports 86 existing findings, and a
follow-up full-head scan reports 156 findings. These include payload email domains and synthetic phone
formats that do not meet the current published-data contract. The conversion commit was pushed before
the failed scan result was inspected; that does not establish source acceptance. Private failed scan:
`catalog-pii-failure-1791068316508907847.log`. Repair payload sources/contracts together and retain original
counts/intents; do not suppress the gate or describe CI alone as complete acceptance.

A new direct origin-nginx ten-operation DVGA probe passed HTTP 200 and all ten nonempty GraphQL values
in 392.963 seconds. Private receipt: `private-nginx-ten-1791068117606041356/receipt.json`.
The strict published-route repeat passed HTTP 200 and all ten nonempty results in 312.906 seconds.
Private receipt: `private-published-ten-1791068470741982694/receipt.json`. The earlier published timeout
remains failed; the complete paced scenario still requires its baseline, all batches and mixed result.
Continuous traffic is being restored on installed `695c459` after focused qualification.

Source candidates advanced to origin `f409d5c` and generator `3973098`; installed candidates remain
origin `d6930ea` and generator `695c459` during their bounded qualification runs. Origin source configures
Juice Shop native seed accounts with the reserved example.com domain on all replicas. Generator payloads
and exact-match contracts use those same native account identities. Mixed DVGA response verification now
requires all ordered result fields and rejects GraphQL errors. Source tests pass 84 origin tests/69 subtests
and 160 generator tests/nine subtests; candidate checks/hooks are recorded separately from installed acceptance.

PII remediation reduced full-head generator findings from 156 to 91, then 20, then 12. Staged English,
fixture and executable changes pass enforcement with zero findings; remaining full-head findings are the
12 existing localized deployment examples, preserved under the fleet English-only/no-locale-refresh policy.
Full-head gate remains failed. Private receipt: `catalog-pii-final-english-1791069127496844001.log`.
Earlier failed scan receipts remain failed. No suppression or sourceHash refresh establishes acceptance.

PII English/scenario remediation is committed in generator `3973098`. Full-head enforcement now
reports exactly 12 remaining localized deployment-example findings; all staged English/source changes
passed enforcement. Private current receipt: `catalog-pii-final-english-1791069127496844001.log`.
Origin and generator required CI passed on these source candidates.

The fresh rendered matrix on installed origin `d6930ea` is under
`private-browser-matrix-1791068709010064608/`. It has two failed CSD HTTP dashboard transport checks;
all content/restoration checks in those receipts passed, but cancellation remains failure. The clear button
reloads the dashboard and the verifier did not await completion before cleanup. Origin `f409d5c` now awaits
that navigation and records the browser error text; a new immutable live check must prove the repair.
The in-progress matrix must finish before origin replacement, then the new source needs its own matrix.

The complete paced DVGA retry on installed generator `695c459` has passed baseline, two-operation and
five-operation JSON checks; ten-operation/mixed checks remain in progress. Continuous service is stopped
while this single shared boundary is occupied and must be restored afterward. Independent origin-nginx
and published ten-operation passes remain focused evidence only; earlier paced timeouts remain failed.

The installed `d6930ea` matrix finished with 66 browser receipts and failed completeness on CSD HTTP
receiver/counter/clear workflows for both domains. Failed evidence remains under
`private-browser-matrix-1791068709010064608/`. The full paced DVGA retry on generator `695c459` ended
at its 900-second deadline: baseline/two/five-operation responses passed; ten-operation client timeout
and mixed cancellation failed. Five intended actions were dispatched, but two cancellations and missing
JSON prevent acceptance. Private receipt: `resume-focused-dvga-costly-query/pass-focused-1791068573345329692/`.

Immutable origin `f409d5c` installed successfully; every Juice Shop replica proved reserved seed domain
and native admin login. Generator `3973098` installed and continuous traffic restarted. CSD focused
repeats still failed; captured error text identifies ERR_ABORTED and one clear-response timeout.
Source `ceb9c06` replaces timed page reloads with in-page Refresh/Clear and adds execution regressions.
The next matrix on `f409d5c` exposed obsolete hardcoded Juice Shop verifier accounts. Four native login
failures were preserved, then only the owned matrix/browser were interrupted. Private evidence:
`private-browser-matrix-1791069786943134526/interruption-receipt.json`.

Current origin source `2990de0` also discovers the account domain from native application configuration
for browser login/basket assertions. Its immutable installation is underway. Generator remains `3973098`.
Focused CSD/Juice verification, fresh full matrix/manual review and complete catalog qualification remain
required. Continuous traffic is stopped during origin update and must restart after fixture/readiness checks.
No failed matrix, timeout or interrupted run establishes acceptance. All task completion gates remain open.

Immutable origin `2990de0` installed successfully. The focused Juice Shop browser run passed all ten
checks under `private-browser-1791070080988673951/`. CSD HTTP repeats passed all five checks, exact fixture
restoration and zero browser failures on both domains under `private-csd-reload-1791070079771721250/` and
`private-csd-reload-1791070097868989406/`. These focused passes qualify the repairs only; the current full
matrix remains in progress and requires manual screenshot review.

A full-catalog prerequisite failure on generator `3973098` exposed unconditional refresh of unrelated
application logins before unauthenticated shadow-endpoint probes. Generator `67e9cf9` declares per-scenario
fixture refresh families and performs no unrelated logins. Source verification passes 163 tests/nine subtests,
Ruff, Biome, pre-commit and staged PII enforcement. Immutable installation passed. The focused shadow scenario
observed all 12 intended GETs across six declared negative endpoints with correct declared outcomes,
zero transport failures and zero cancellations. Private receipt:
`resume-focused-shadow-fixture-scope/pass-focused-1791070343496603947/receipt.json`.
Earlier zero-launch prerequisite evidence remains failed. Continuous traffic restart is underway on `67e9cf9`.

Current source/installed origin is `2990de0`; generator is `67e9cf9`. WAAP pins those archive/installer digests.
Provider remains 13.0.2 with enriched v10.0.0 provenance. All T01–T16 completion gates remain open.

Generator source/installed candidate is now `551428e`, which also rejects missing, duplicate and unknown
fixture-refresh declarations. Source checks pass 168 tests/nine subtests and staged PII/pre-commit.
The installed shadow-scenario repeat passed all 12 intended GETs with zero transport failures/cancellations.
Private receipt: `resume-focused-shadow-fixture-scope/pass-focused-1791070532637659694/receipt.json`.
Continuous restart is underway on this exact source. The fresh origin `2990de0` matrix is in progress;
its first 27 browser receipts passed with no failures. No full acceptance is claimed.

Generator source/installed candidate is `82646ba`. Native timed-worker requests now carry opaque
worker markers in private dispatch/response/error receipts; benign transport failures record application
path and elapsed time. Source checks pass 169 tests/nine subtests; native ApacheBench regression is skipped
on the workstation where the binary is unavailable, but the owned generator loopback probe passed.
The first worker-marker install failed ApacheBench argument placement and was interrupted after preserving
its tool-failure receipt. Corrected immutable `82646ba` is running the full ten-minute stress retry.
Continuous service is stopped while that single shared boundary is occupied and must restart afterward.

The latest 46-second rate slice on `551428e` reached 196.88 aggregate RPS and 99.93 percent benign success,
but six TimeoutError baseline transport failures fail acceptance. Earlier zero-failure slices do not override
this receipt. Current origin `2990de0` full matrix has 62 passing browser receipts/no failures so far;
complete matrix and manual screenshot review remain pending. All final acceptance gates remain open.

The complete installed origin `2990de0` matrix passed with 66 browser receipts, no missing workflow/layer
entries and zero recorded browser failures. Private matrix: `private-browser-matrix-1791070127766279518/`.
All 315 screenshots were collected; eight application contact sheets and full-size key pages were reviewed.
Manual review still rejects rendered completeness because a Juice Shop About gallery remains a loading
spinner on one HTTPS capture. Private review: `manual-render-review-2990de0.json`. HTTP/DOM matrix success
does not override that visual limitation. Remaining gallery resource behavior is under investigation.
Corrected native stress `82646ba` is running with worker attribution and zero failures/cancellations through
its first four minutes; full ten-minute completion remains pending. Continuous service restart follows.

Manual gallery investigation found lazy carousel images and no broken published asset prefix. Origin source
`644b9f5` now advances through each native Next control and requires the active image to load before accepting
About content; immutable installation is underway. The prior `2990de0` matrix stays automated-pass/manual-
incomplete, with 315 reviewed screenshots and the loading-state limitation retained.

Generator source `b352c64` repairs required native-regression CI typing, protocol-method naming and Ruff
annotation placement; Pylint/mypy/Ruff pass directly. Installed stress remains `82646ba` so its receipt stays
bound to its original revision. Corrected native workers pass nine minutes so far without transport failures
or cancellations; final drain/native report verification remains pending. Earlier argument-order failure is
preserved as tool failure and interrupted after confirmed error.

Installed origin `ecb553e` passed the stricter HTTPS API Juice Shop browser run: ten checks, zero failures,
including populated lazy gallery navigation. Private receipt: `private-browser-1791071785759617282/`.
Current full matrix on this strengthened verifier is running; prior complete `2990de0` matrix remains
automated-pass/manual-incomplete. Gallery screenshot re-review is pending.

Corrected ten-minute native stress on installed `82646ba` completed all intended dispatches but remains
failed for 20 client cancellations: two per wrk worker and one per ApacheBench worker at timed completion.
Worker markers and timestamps now bind that behavior to completed native reports. Final receipt remains
tool_failure; those cancellations are not ignored or relabeled. Continuous traffic restarted on installed
`b352c64`; final fixture/scenario/load/rebuild gates remain open. All failed evidence is retained.

The stronger Juice Shop About gallery screenshot on installed `ecb553e` was reviewed full-size and
shows loaded media/feedback without a spinner. Current complete matrix is still in progress on that source.
A 46-second continuous slice on generator `b352c64` reached 197.15 aggregate RPS, 100 percent benign success
and zero baseline transport failures across all nine applications. This is short-window evidence only.

Current full catalog reached twelve accepted scenario receipts, then the headless form scenario failed
with zero native submissions, browser navigation timeouts and seven cancellations. Source request evidence
shows assets starting 13–25 seconds after navigation. Generator `6345562` uses 60-second bounded navigation
and request-drain waits; its immutable focused retry is running. Preserve the failed `b352c64` catalog receipt.
Generator `9b5d9b8` also records whether failed native requests had actually reached upstream, so future
stress cancellation diagnostics distinguish queued requests from dispatched ones. No acceptance gate ignores
client cancellation. Current pins are origin `ecb553e` and generator `6345562`; continuous restart follows
focused qualification. All complete-catalog/rebuild/final gates remain open.

Installed generator `6345562` passed the focused native form retry: two real registration POSTs and two
real feedback POSTs, HTTP 201, 74 total browser requests, zero transport failures/cancellations. Private
receipt: `resume-focused-native-form-deadlines/pass-focused-1791072238177746645/receipt.json`. This qualifies
actual form dispatch only; isolated account/feedback cleanup and repeatability remain required. The failed
zero-submission catalog run remains failed. Continuous traffic restart is underway on the fixed source.
Current origin `ecb553e` matrix has 32 passing browser receipts/no failures so far.

These earlier observations retain their original source revisions and failed evidence;
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

Origin `d6930ea` preserves native simulate_load iteration counts and 0.1-second delays while using
gevent cooperative sleep, preventing the deliberately expensive query from blocking all replica
requests. Source verification passes 83 tests/69 subtests and hooks. Immutable installation and native
concurrency proof are running; full expensive batch acceptance remains open. Source pins updated.

Cooperative DVGA native proof passed on all four replicas: expensive systemUpdate retained 20–50-second
duration and correct JSON while simultaneous __typename returned in 6–8 ms. Private source-bound receipt:
`private-cooperative-dvga-1791065993259661683/receipt.json`. Origin immutable installation passed on
`d6930ea`. Published complete batch, final rendered matrix, catalog and fresh rebuild gates remain open.
Continuous pass retains credential-stuffing failure for thirteen of fifteen actual submissions after
two login-form setup errors; it cannot establish catalog acceptance.

Generator `1e79a44` retries only login-page setup for transient 502/503/504 with a bounded three-attempt
limit and longer browser deadline; all fifteen credential pairs remain unchanged and actual submissions
are counted. Previous thirteen-submission failure remains failed with its explicit HTTP 503 evidence.
Cooperative DVGA full published batch qualification is in progress; native responsiveness proof passed
all replicas without changing original load duration. No full catalog/fresh acceptance is claimed.

Generator `9a514f8` serializes shared RESTaurant role/crAPI video mutations with bounded per-fixture
locks, preventing nested actors from racing restoration. Source checks and catalog dependency validation
pass; installed nested qualification remains pending. Cooperative DVGA published baseline/two/five-operation
JSON responses passed; ten/mixed remain running. Native ten-operation comparison is retained separately.

Native ten-operation systemUpdate probe on cooperative origin returned HTTP 200 with complete JSON
in 323 seconds, preserving all operations. The paced published counterpart remains pending; a direct
published comparison is running to distinguish proxy behavior from WAAP serving. Results remain
provisional and cannot establish full batch/catalog acceptance.

Full published batch on cooperative origin remains failed: ten-operation request hit its 600-second
client timeout, then the mixed request was interrupted at the 900-second scenario deadline. Every
dispatch launched but response/content acceptance did not pass; two cancellations remain failure.
Native ten-operation comparison passed HTTP 200 in 323 seconds. Direct published comparison remains
running; the request path difference must be reconciled before acceptance. Continuous traffic is being
restored on current immutable generator.

Active continuous candidate `9a514f8` measured 197.13 aggregate HTTP RPS and 177.59 benign RPS in a
46-second window, with 100 percent benign success, all nine rotated application paths and zero baseline
transport failures. This is a focused window only, not sustained fresh-deployment acceptance. Current
full pass has eight passing receipts/no failures. Direct published ten-operation DVGA comparison is still
pending beyond native completion time; no complete catalog is accepted.

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

Native acceptance continuation: provider v13.0.3 was confirmed against the release API and installed from the
Registry with signing key 7282C542DC88E217. Both Terraform roots validate. Generator `1f71d00` separates
catalog dispatch success from native functional acceptance. Only explicitly declared functional contracts can
qualify; missing contracts fail acceptance. Existing source test doubles are development checks, not live
acceptance. No full catalog or clean-rebuild acceptance is claimed.

Native community exposure qualified on installed `1f71d00`: the intended GET returned populated native posts
with synthetic author.email values; upstream dispatch and content assertions passed with zero transport
failures/cancellations. Private receipt: `resume-focused-native-community/pass-
focused-1791078117999254011/receipt.json`. This is one scenario contract, not full catalog acceptance. AWS STS
confirms refreshed credentials usable on the Ubuntu workstation.

Native credential outcomes qualified on installed `f121f61`: fifteen POSTs, one authenticated native DVWA
page, fourteen explicit login rejections, logout cleanup, fifteen screenshots, zero
browser/transport/cancellation errors. Private receipt `resume-focused-native-credential-outcomes/pass-
focused-1791078365167682691/receipt.json`; representative success/rejection screenshots manually reviewed,
remaining rejection digests identical.

Generator `bdbba8b` rejects failed authentication renewal instead of reusing stale tokens. Native crAPI valid-
invalid-valid login sequence passed (`resume-native-auth-failure/pass-
focused-1791078570276914525/receipt.json`). An overlapping focused boundary failed to start and remains failed
evidence; reruns must be sequential. Full rendered matrix on current origin is running; full catalog
acceptance and clean rebuild remain open.

Current origin `cb08457` completed the full declared application/workflow matrix: 66 browser receipts,
complete true, no missing checks or failed workflows, and 315 screenshots. Matrix `private-browser-
matrix-1791078210428199853` and private `manual-render-review-cb08457.json` bind source and review. Eight
application contact sheets plus full dashboard/ReDoc/community views were manually reviewed. This is current
candidate application qualification; final merged clean deployment remains required.

The a88c94e both-domain run failed: api-domain credential attempts 13 and 14 did not drain within the inherited 15-second helper deadline, leaving only thirteen native POSTs. The run remains failed. Generator `5d589b2` aligns every credential drain/navigation deadline to sixty seconds and records pending resource paths; both-domain installed qualification is running.

Both native functional contracts passed through both WAAP domains on installed `5d589b2`: thirty credential
POSTs with two valid logins, twenty-eight native rejections and logout cleanup, plus two community exposure
actions; zero transport failures/cancellations. Private accepted receipt `resume-native-functional-both-
domains/pass-focused-1791079166467472534/receipt.json`. The previous a88c94e two-domain failure remains
failed. Only two of 164 scenarios have explicit functional contracts; 162 remain unqualified.

Provider 13.0.3 binary source matches `b1854d740269b420e238aed9e8a556d0bb084164`; binary SHA256 `43898dc1fd9010c925c03ff27d32981d2c27095aee7a3cac1485a22c0683762c`. It retains enriched API v10.0.0 commit and verified pin/bundle digests. Private `ecosystem-provider1303-receipt.json` records installed provenance; the earlier 13.0.2 receipt remains historical evidence.

Generator `469d821` passed both implemented native contracts on both domains and proved a functional slice cannot establish whole-catalog acceptance (`resume-native-functional-both-domains/pass-focused-1791079630254357954/receipt.json`). Required CI passed. One-shot execution now fails incomplete functional acceptance and receipts list unqualified scenario IDs.

Origin `0a2d4aa` and generator `aec137d` replace fabricated CSD no-op JavaScript with five pinned native
libraries served on the owned origin; browser loader completion requires the native exported function. Origin
immutable provisioning completed successfully; installed asset/browser qualification is pending. Prior cb08457
full matrix remains qualified historical evidence; the new source requires current verification.

All 45 native library asset checks passed: four CSD replicas, origin nginx, and both domains over HTTP/HTTPS
returned the pinned JavaScript bytes/content type. Generator aec137d completed three real library browser
actions with cleanup, zero transport failures/cancellations and native function exports present. Generator
8a48eea adds explicit functional contracts requiring finished library states plus source-bound
screenshot/cleanup evidence; two-domain qualification is running. Required origin CI passed.

Three native CSD library contracts passed on both domains on 8a48eea: all libraries finished, screenshots
matched their digests, browser cleanup passed, zero transport failures/cancellations. Private accepted receipt
`resume-native-csd-libraries/pass-focused-1791080268058194884/receipt.json`. Generator 69fdd8f additionally
verifies pinned library versions and Day.js date behavior; installed rerun is in progress. Five of 164
scenarios now have explicit functional contracts; 159 remain unqualified. CSD remains disabled and no control
detection is claimed.

The stricter 69fdd8f native library version/behavior contracts passed all six runs across both domains with
zero transport failures/cancellations and verified cleanup/screenshots. Private receipt `resume-native-csd-
libraries/pass-focused-1791080407279148227/receipt.json`. Five functional contracts are declared; 159
scenarios remain unqualified. A current origin matrix is running on 0a2d4aa; prior complete cb08457 evidence
remains preserved.

Generator 69fdd8f completed all five declared functional contracts through both WAAP domains with zero
transport/cancellation failures. Credential/community receipt `resume-native-functional-both-domains/pass-
focused-1791080493447587380/receipt.json` also verifies functional-slice true and whole-catalog accepted
false. Required CI passed. Current generator 369d54b adds measured native slow-header launch spacing and
incomplete-header evidence; two-domain installed qualification is running.

Native slow-header contract passed on both domains on 369d54b: twenty TLS connections per domain, measured
attempt spacing within the configured limit, three partial-header rounds, peer closure observations and all
sockets closed; zero transport/cancellation failures. Private receipt `resume-native-slow-header-
functional/pass-focused-1791080725732053859/receipt.json`. Six functional contracts declared, 158 remaining
unqualified. Native scanner tool semantics and broader mutation recovery remain open.

Installed one-shot SSL suite verification correctly returns exit code 1 with functional_verified false and all three missing native scanner contracts listed. This is an acceptance-gate check, not scanner functional acceptance. Current continuous service is active/enabled on 369d54b with no current failures.

Current origin 0a2d4aa full matrix completed: 66 browser receipts, complete true, no missing checks/failures,
315 screenshots; eight contact sheets and four full page views manually reviewed. Private matrix `private-
browser-matrix-1791080250331268526`, review `manual-render-review-0a2d4aa.json`. Short 46-second live window
on 369d54b measured 197.30 aggregate HTTP RPS, 100 percent benign success and zero baseline transport failures
across nine applications. Final sustained fresh-deployment acceptance remains open.

Generator 8cf4d62 adds explicit native DVWA command output contracts for all nine preserved payloads, including specific backtick failure behavior. Source checks passed 173 tests/nine subtests plus shell/Ruff/mypy/Pylint; these remain development checks. Immutable installed two-domain qualification is running; six earlier functional contracts remain qualified on their recorded revisions.

The 8cf4d62 command qualification failed: all eighteen published attempts returned mitigation-candidate HTTP
403 and no native output. Direct native checks on all four DVWA replicas exposed missing ping: seven payloads
returned expected command data, while && hostname and backtick behavior could not complete. These runs remain
failed. Origin dc99bef adds required iputils-ping to the immutable DVWA image; rebuild is running. Command
verifier CI formatting is repaired in e3dbf0c. Native behavior and control attribution remain separate gates.

Immutable origin dc99bef provisioned successfully and required CI passed; native ping is installed on every
DVWA replica. Native command checks now return expected output for eight payloads; the preserved backtick case
returns successful ping output with no command stdout. Generator 48d4b62 declares that observed negative
explicitly. Exact-script native diagnostic failed with HTTP 302 because published path/cookie scope was
applied to native routes; that diagnostic remains failed, and correct native-route checks are running.
Published command coverage remains unqualified: prior requests returned 403, with no attributed control
evidence yet.

Correct native-route command verification passed all 36 checks across four repaired DVWA replicas, including
eight command-output payloads and the explicit backtick no-stdout negative. Private receipt `native-command-
replica-1791083233418015195.json`. Published command scenario remains unqualified pending attributed blocked
outcomes; no command-execution success is inferred from HTTP 403. Continuous startup completed on 48d4b62;
fresh status and dc99bef full matrix are pending.

The dc99bef current matrix completed successfully with 66 browser receipts, complete true and no missing
checks/failures (`private-browser-matrix-1791082428479897763`). Screenshots are retained. Command attribution
probes failed before querying security events because scratch actor names did not match the existing
synthetic-user validator; those tool failures remain failures. No attributed command mitigation is claimed.

Current dc99bef rendered review passed across eight contact sheets plus detailed DVWA/DVGA and dashboard/ReDoc/community views. Matrix complete true, 66 receipts, no missing checks/failures, 315 retained screenshots. Private manual-render-review-dc99bef.json binds the current revision. This remains candidate application qualification, not final merged rebuild acceptance.

Command mitigation attribution completed with a valid unique waf actor: eighteen published requests returned
HTTP 403; nineteen telemetry events contain eighteen matching WAF block events for /dvwa/vulnerabilities/exec/
plus one malicious-user event. Private native-command-control-1791083672548227999.json binds source, origin
and request window. Native 36-check qualification is separate. The reusable command scenario remains
unqualified until its contract joins these evidence layers; earlier strict-output and actor-validator failures
remain failures.

Reusable verify_command_coverage.py passed against real native and control receipts: exact 36 native
replica/payload inventory, eighteen published blocked requests and eighteen unique attributed WAF events, nine
per domain. Private native-command-coverage-join.json retains evidence digests. This standalone evidence join
qualifies the observed behavior/control pair; the generator command scenario still needs runtime integration
and cannot establish whole-catalog acceptance.

Source-bound command evidence join passed: native receipt native-command-replica-1791084141577599479.json
records installed origin dc99bef and all 36 native checks; matching control receipt supplies eighteen unique
WAF block events across both domains. Private native-command-coverage-join-bound.json records input digests
and all checks true. The older join without native source binding is retained as superseded, not final
acceptance. Runtime command contract integration remains required.

Generator 804c06f tightens native hostname output matching to the actual container hostname format. Source checks passed 173 tests/nine subtests. Immutable artifact installed; continuous startup is in progress. The published command scenario remains unqualified despite standalone native/control evidence, pending runtime join integration.

Native Masscan diagnostic completed actual SYN/SYN-ACK probes to owned application ports 80 and 443 at one
packet/sec with packet trace. Generator 6529de0 replaces the generic TLS substitute for that catalog entry
with the native Masscan binary, exact ports, packet-level launch/reply and pacing assertions, plus
binary/report/source digests. Source tests/Ruff/mypy/Pylint passed; immutable installed two-domain
qualification is running. The diagnostic alone is not catalog acceptance. Required WAAP CI passed on aacd269.

Installed native Masscan contract passed on both domains on 6529de0: two intended SYN probes per domain,
actual SYN-ACK replies from ports 80/443, measured pacing, binary/native report digests and zero
transport/cancellation failures. Private receipt `resume-native-masscan-functional/pass-
focused-1791085027630506301/receipt.json`. Seven functional contracts have live qualification; command remains
separately native/control-qualified pending runtime join.

Current 6529de0 continuous service is active/enabled. A 46-second live window measured 197.08 aggregate HTTP RPS, 100 percent benign success, zero baseline transport failures, and benign requests rotated across all nine applications. This short window is not final sustained fresh-deployment acceptance. Current generator/WAAP CI remains pending.

Native-tool substitution audit is source-controlled in traffic-generator docs/en/native-tool-remediation.md.
Five scanner entries now execute actual Nmap/SSLScan/SSLyze/testssl with scoped connect pacing and native
structured reports; installed f4f30ce completed all five. Seven load and two benchmark paths execute native
wrk/hey/curl/Vegeta/ab/Lua instead of Python requests; cache/client paths use native cURL. Native Subfinder
returns real provider discoveries. Dummy tokens, fabricated OTP 0000, fallback session IDs, browser response
substitution and chained privilege substitution are removed. Unfinished native signup/reset recovery and full
benchmark functional assertions remain explicit gaps. Native OpenSSL slow-header cleanup fixed after real peer
408/BrokenPipe failure; installed c645c3f rerun pending. Failed evidence remains failed.

Native substitution continuation: generator `799e360` passed complete native SSLyze checks on both domains.
Each run recorded 602 scoped, paced connection attempts, all 18 mandatory plugins completed, zero transport
failures and no surviving process group. Private receipt:
`resume-native-scanner-completeness/pass-focused-1791120982851266086/receipt.json`.
The partial-plugin candidate remains failed evidence. The native crAPI MIME parser passed against 17 actual
MailHog messages containing welcome VINs and reset OTPs; this is parser verification only, not isolated
signup/reset scenario acceptance. Generator `312f665` is installed for native benchmark follow-up and now
requires observed process cleanup for native load workers instead of a hardcoded cleanup assertion.
Source validation passed 176 tests, nine subtests, lint, type checks and staged PII checks; one workstation
native-tool test remains environment-skipped and is not live acceptance. Full catalog, benchmark semantics,
fixture recovery, merged installation and clean rebuild acceptance remain open.

The installed `312f665` native benchmark follow-up completed 17 keepalive workers and 33 VM-comparison
workers with observed process cleanup and zero transport failures/cancellations. Both remain
`functional_verified=false`; dispatch and report completion do not establish complete benchmark coverage.
Private receipt: `resume-native-followups/pass-focused-1791121335656328761/receipt.json`.
Two crAPI video header placeholders are replaced in generator source with native FFmpeg encoding and
FFprobe codec/dimension verification. Workstation encode/decode passed; installed application acceptance
is pending. Clean generator provisioning now installs FFmpeg rather than relying on a guest-only package.

Generator `3e8ba7b` is installed with native FFmpeg/FFprobe. Both real-media scenarios dispatched their
required actions with zero transport failures and zero cancellations; exact disposable video cleanup and
seeded video restoration passed. Private receipt:
`resume-native-real-video/pass-focused-1791121960307112217/receipt.json`.
Both remain functionally unqualified: WAAP mitigation and native application rejection were observed,
and complete conversion/control contracts remain required. No exploit-success claim is inferred.

Origin `5d705bf` replaces the seeded MP4 header placeholder with actual native-encoded video bytes.
Immutable installation passed, and two installed fixture reruns preserved the video row ID and row count
with identical 1,693-byte media (`b3199164a035856e194b2fe5bf5beec14d608e578a0606c294e988215457ab14`).
Private receipts: `remediation-immutable-origin-1791122375841996096/receipt.json` and
`native-video-seed-1791122493176878462/receipt.json`. Native FFmpeg decoded all generated frames;
source metadata retains the exact generation command and bytes. Source checks passed 86 tests and
69 subtests. Complete application-matrix acceptance for this new origin revision remains required.

Generator `d85254c` is installed with the final native full-frame decode check and required CI source
formatting repairs. Installed FFmpeg encoding and full-frame decode passed. Prior candidate receipts
remain bound to their own revisions; new full catalog and application/control qualification remains open.

Origin `e492b9f` adds isolated signup login and an actual emailed OTP password-reset workflow, including
new-password login, rejection of the old password and exact account/OTP/welcome-vehicle/mail cleanup.
The workflow exposed upstream `jwt_token varchar(500)` rejecting valid long synthetic email identities;
source provisioning now widens that column to text and clears identity prepared plans only after a schema
change. Two staged native runs passed all six checks and recovery. Immutable installation passed.
The earlier `c476e25` six-layer receipts pass API workflow and cleanup but premature public MailHog
screenshots remain failed rendered evidence; final `e492b9f` now requires the owned recipient in the
rendered inbox and is undergoing six-layer qualification. Traffic catalog signup/reset integration and
complete application/catalog/rebuild acceptance remain open.

Installed origin `e492b9f` passed all six isolated signup/reset layers: native crAPI, origin nginx,
and both WAAP domains over HTTP and HTTPS. Each layer passed signup, exact welcome-mail ownership,
actor-bound login, native reset-mail OTP, new-password login, old-password rejection, rendered owned
inbox rows and exact recovery. Private receipt:
`private-browser-reset-layers-1791123790012229844/receipt.json`.
All twelve final signup and MailHog screenshots were manually reviewed; private review receipt:
`native-reset-render-review-e492b9f.json`. Earlier premature-render evidence remains failed.
This qualifies the added application workflow only; traffic catalog signup/OTP scenario ownership,
full current-source application matrix, full catalog passes and rebuild acceptance remain open.

Origin `94cc186` extends the isolated signup workflow to register the actual welcome vehicle using
its native emailed VIN and pincode, confirm exactly that VIN under the same authenticated actor,
and recover only the journaled vehicle owned by that account. Staged native execution passed all
seven workflow checks and recovery; immutable installation passed. Seven-check serving-layer
qualification is running. The prior `e492b9f` reset/render receipts retain their narrower scope.

Installed origin `94cc186` passed all seven isolated signup/vehicle/reset workflow checks on native
crAPI, origin nginx, and both domains over HTTP and HTTPS, with exact fixture recovery on every layer.
Private receipt: `private-browser-reset-layers-1791124218429313371/receipt.json`.
All twelve final signup and MailHog screenshots were reviewed; private review:
`native-reset-render-review-94cc186.json`. Source checks passed 86 tests and 69 subtests.
This is bounded application workflow acceptance; recurring catalog signup/OTP ownership integration,
full application matrix, complete catalog, merged sources and clean rebuild remain open.

Origin `9dec3a1` provisions a distinct synthetic OTP mutation actor. Native validation changed its
password with the actual emailed OTP, authenticated with that changed password, then restored the
original password and removed only new owned mail. Generator `df6995d` launched both sampled OTP
batches (30 guesses/domain) on both domains with password/mail restoration and zero transport failures,
but remained functionally unqualified. Generator `88010ad` now requires actual reset-mail prerequisites
and every native guess response before functional acceptance; installed both-domain verification is
running. Failed source/CI/live receipts remain preserved; recurring signup catalog integration and final
complete catalog/rebuild remain open.

Installed generator `88010ad` passed the isolated native OTP functional contract on both domains:
actual reset-mail prerequisite, all 30 guesses per domain with native OTP response assertions,
password/mail restoration, zero transport failures and zero cancellations.
Private receipt: `resume-isolated-native-otp/pass-focused-1791125103668191469/receipt.json`.
This is bounded sampled OTP coverage, not full-keyspace feasibility or WAAP control attribution.
Recurring signup catalog integration and the complete catalog/rebuild gates remain open.
