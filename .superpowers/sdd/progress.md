# SP3 progress ledger
Issue: #41  Branch: sp3-api-protection
Spec: docs/superpowers/specs/2026-07-14-sp3-api-protection-design.md
Plan: docs/superpowers/plans/2026-07-14-sp3-api-protection.md
Execution: INLINE (like SP1/SP2 — sequential live matrix on shared azurerm state + schema iteration).

Task 0: complete (branch sp3-api-protection; issue #41; spec + plan written; design approved).
Task 1: complete (client-matcher, 4/4)
Task 2: DEFERRED (standalone xcsh_rate_limiter_policy) — its rule spec's apply_rate_limiter is an empty marker; a functional policy needs a separate xcsh_rate_limiter object + deep per-rule matcher/action oneofs (advanced server-scoped path). The inline LB rate_limit.rate_limiter (Task 3) carries the full rate spec self-contained and covers the common case. Documented deferral (approved "defer exotic sub-arms" boundary).
Task 3: complete (rate_limit inline, 7/7)
Task 4: complete (xcsh_sensitive_data_policy)
Task 5: complete (sensitive_data_policy_choice + data_guard_rules, 12/12; disclosure_rules deferred)
Task 6: complete (api_protection_rules, 16/16)
Task 7: complete (validation_custom_list, 18/18)
Task 8: complete (root passthrough + 0-change verified)
Task 9: complete (generator 6/6 + harness, 13 variants)
Task 10: IN PROGRESS — live matrix run 1: 3 PASS/others 400 (missing metadata + request_validation_properties). Fixed (46245ad) + invert_matcher explicit. Run 2: 5 PASS/8 FAIL. Root-caused to PROVIDER codegen gaps (not module):
 (a) api_protection_rules + ip_prefix/ip_threat client_matcher -> any_client empty-marker materialized on read ("was absent, now present"; nested empty-oneof-marker class, cf WAF #1082);
 (b) validation_custom_list -> round-trip import-drift (server-materialized optionals in deep block);
 (c) invert_matcher Optional-scalar (worked around by explicit false).
LIVE-CLEAN arms verified: rate_limit, sensitive_data(custom), data_guard, api_protection w/ any_client (pair-007 round-trip PASS). Canonical restored (LB healthy).
DECISION POINT for user: (A) lock-step provider codegen fixes [correct, large] then full-green matrix; or (B) ship SP3 with clean arms live + provider-gap combos plan-tested-only + documented follow-ups.
Task 10 CHECKPOINT: provider fix root-caused + designed (provider branch fix/sp3-nested-marker-and-optional-scalar-suppression, SP3-PROVIDER-FIX-DIAGNOSIS.md committed). Fix = preserve planned block + patch object-ref tenants (merge), incl. LIST-element positional preservation (render.go:858 stateBase="" gap). This regenerates ALL 128 resources -> delicate; warrants a focused, fully-tested pass (like the SP2 resume). SP3 module 100% done + 18 plan-tests + 6 gen-tests committed; canonical restored. REMAINING: provider codegen refactor -> regen/build/release -> re-run matrix to green -> whole-branch review -> PR (#41).

## 16:39 provider codegen fix — apply-path CONFIRMED
- render.go 2 changes (state-threaded reconstruction): SpinePreservesOffSpineLeaves + list positional preserve. 2 new TDD tests green; full `go test ./tools/... ./internal/...` green; 128 resources regen+compile; webapp defaults 0-change (no regression).
- Live matrix variant 001 (ip_prefix+custom_list): FAIL **import-drift** NOT not-idempotent → apply-path 'inconsistent result after apply' (any_client/invert_matcher) is FIXED. Remaining: any_client (server-default oneof base marker) materializes on IMPORT path (isImport bypasses threading by design) → needs import-default-suppression (like enable_api_discovery). validation_custom_list leaf TBD from matrix.
- NEXT: full matrix → reproduce pure ip_prefix (004) + pure custom_list (006) drift → batch suppress in tools/import-default-suppressions.json + seed + TDD → regen → rerun matrix → release.

## 17:14 suppression fix applied + matrix2 running
- Confirmed drift leaves (live isolation): variant 004 → `any_client {}` (client_matcher base marker); variant 006 → `skip_response_validation {}` (validation_mode response sub-oneof).
- Added both to HTTPLoadBalancer import-default-suppressions (JSON + Go seed) + TDD TestImportSuppressions_APIProtectionServerDefaults (green). Regen+build+full `go test ./tools/... ./internal/...` green; defaults 0-change.
- matrix2 (PID 84819) rerunning with fixed binary. Expect all PASS/SKIP. Prior run: 5 PASS / 8 FAIL(import-drift 001-006,008,010).
- Provider fix = 2 render.go changes (state-threaded reconstruction) + 2 suppressions. sp3-findings.md provider section updated (items 3+4).

## 21:09 provider review CLEAN + any_ip fix + matrix3 (authoritative) running
- 3rd drift leaf found (variant 002/010 isolation): `any_ip {}` = default source-IP sub-oneof member inside client_matcher ip_threat_category_list. Added to suppressions (JSON+seed) + test extended. 002 & 010 re-verified round-trip CLEAN individually; canonical restored 0-change.
- pr-review-toolkit:code-reviewer on provider source diff (6 files, +201/-26): NO findings at/above threshold. Confirmed nil-safe emitted Go, no regression to 3 existing object-ref tests, threading no-op for non-ref blocks, real behavior assertions in 2 new tests. 2 sub-threshold notes: any_ip breadth (audited: 56 occ, all optional empty-marker oneof members, never Required → safe; ack in PR), seed+JSON DRY (keep, matches precedent).
- matrix3 (PID 32006) authoritative full run in progress; expect 13/13 PASS. Then: commit tools/** → release → versions.tf bump → webapp PR (Closes #41).

## 21:36 authoritative matrix 13/13 + provider PR opened
- matrix3 AUTHORITATIVE: **13/13 PASS, 0 FAIL, 0 SKIP** (pre-fix 5/13). sp3-findings.md table filled (scratch; docs/superpowers gitignored).
- Provider: issue #1095 + PR #1096 opened (branch fix/sp3-nested-marker-and-optional-scalar-suppression, commit 77dc057f, tools/** only +201/-26). gofmt/vet/json clean. CI running, auto-merge enabled.
- Module needs NO further change: invert_matcher=false + ip_prefix_list.invert_match stay DECLARED (plain Optional bools → import-clean by declaration; only oneof base markers any_client/any_ip/skip_response_validation are suppressed).
- REMAINING: watch #1096 CI→merge → auto-regen PR merge → Tag-and-Release new version → bump webapp terraform/versions.tf → push sp3-api-protection → webapp PR (Closes #41) → CI green → sync main → memory (SP3 done, next SP4 api_testing/SP5 traffic-gen).

## 22:32 provider v3.71.3 RELEASED + webapp versions bumped
- Provider release chain COMPLETE: #1096 merged → auto-regen PR #1098 merged (CI green) → **v3.71.3** published (not draft, 14 assets) + **indexed in Terraform registry**.
- webapp: terraform/versions.tf bumped to >= 3.71.3 (commit 017a83d, #41); fmt clean. Branch sp3-api-protection now 9 commits ahead of origin/main (not yet pushed).
- Whole-branch code review dispatched (webapp SP3 diff: 17 files +1208/-17). Then: address findings → push → webapp PR (Closes #41) → CI → sync main → memory (SP3 DONE).

## 22:42 whole-branch review addressed + webapp PR #42 opened
- Whole-branch review (webapp SP3): 1 Important finding — sensitive-data policy two-knob desync (enabled vs choice). FIXED: collapsed to single choice knob (count = choice==custom), dropped enabled var (module+root), derived output+2 plan-tests+generator from choice (commit e17e2dd). Config-equivalent for all matrix variants → 13/13 still holds. 18/18 plan-tests + 6/6 generator + fmt/ruff green.
- webapp PR #42 opened (Closes #41), branch pushed (10 commits). CI: linked-issue/plan/shell/translation PASS, Lint Code Base pending, auto-merge enabled.
- REMAINING: #42 CI→merge → sync main → update auto-memory (SP3 DONE; next SP4 xcsh_api_testing, SP5 API traffic-gen).

## 22:53 SP3 COMPLETE ✅
- webapp PR #42 MERGED (issue #41 CLOSED), all CI green incl Lint Code Base (ruff-format fix). provider issue #1095 CLOSED.
- Both mains synced (webapp 49ba983; provider 446bbcef). Feature branches deleted (local+remote). Dev-override binary rebuilt from main = released v3.71.3 (registry-indexed). Temp cleaned.
- Memory updated: SP3 DONE, MEMORY.md pointer + roadmap file. NEXT = SP4 xcsh_api_testing, SP5 API traffic-gen.
- FINAL: provider v3.71.3 released; SP3 live matrix 13/13; all 11 SDD tasks complete.

## 01:36 SP4 module + tests + generator/harness DONE; live matrix running
- SP4 (API Testing) issue #45, branch sp4-api-testing. Module both surfaces (standalone xcsh_api_testing + schedule oneof every_week-suppressed/day/month; LB api_testing_choice inline block); 5-arm credential auth (admin/standard/api_key/basic_auth/bearer_token) + clear/blindfold SecretType (reuses locals_api convention). custom_header_value REQUIRED by resource → defaulted 'f5xc-api-testing'. Single-knob selectors (SP3 lesson).
- 16 plan-tests (api_testing.tftest.hcl) PASS; defaults 0-change live; 7 generator tests PASS; ruff/shellcheck/shfmt clean. Commits 207a17d (module) + 6b0cc60 (generator+harness+Makefile).
- Live matrix (PID 94050, 17 variants) RUNNING. Flags: LIVE(admin/standard), SECRET(clear api_key/basic_auth/bearer→write-only re-apply gate), SKIP(blindfold→platform 500). WATCH: credentials[] is list-nested-oneof w/ SecretType object-refs — the class SP3 v3.71.3 fix targets; matrix verifies or surfaces new provider work.
- REMAINING: matrix→all PASS/SKIP (provider lock-step if gaps)→canonical→whole-branch review→PR Closes #45→CI→main→memory SP4 done (next SP5 traffic-gen).

## 01:59 SP4 module DONE + rescoped to real API; provider gap #2 diagnosed
- Live API probing corrected SP4 surface: credentials_choice={api_key,basic_auth,bearer_token} only (admin/standard 400=excluded); domain needs >=1 credential (else 500); every credential needs a secret. Module (both surfaces) + 13 plan-tests + 7 generator tests green; defaults 0-change; ruff/shellcheck/shfmt clean; $RANDOM->CSPRNG. Commits 207a17d,6b0cc60,69e57a1 on branch sp4-api-testing (issue #45).
- BLOCKER (provider lock-step #2, well-diagnosed): live apply of a credential -> 'inconsistent result after apply: domains[0].credentials[0].standard was absent, now present'. 'standard' = server-default credentials_choice base marker (server echoes it). ROOT CAUSE: generated read-back renderUnmarshalSingleChild empty-marker branch, LIST-container case (render.go ~744-748), preserves marker PRESENCE only ('if state.Field!=nil return &Empty{}') then falls through to response-populate -> materializes the server echo when plan omitted it. SP3 fixed SINGLE-container markers (return stateBase.Field, preserving absence) but not list-element markers. FIX: make the list-container empty-marker branch also return stateBase.Field (guarded by the len stateGuard) when !isImport, mirroring single; + import-default-suppress 'standard' for APITesting. Regenerates 128 resources (same category as SP3 v3.71.3).
- REMAINING: provider fix (render.go empty-marker list-container absence-preserve + APITesting 'standard' suppression) TDD -> regen/test -> release vX -> bump versions.tf -> re-run api-testing-matrix (SECRET write-only gate + blindfold SKIP) to all PASS/SKIP -> whole-branch review -> PR Closes #45 -> memory. Then SP5 traffic-gen.

## 02:29 SP4 provider fix #2 committed + PR #1100 (validated live)
- Root cause: credentials[] is a list nested in the domains[] LIST element; read-back positional threading only engaged for list-in-SINGLE (container==single), so credentials got stateBase='' → server-default marker 'standard' materialized + write-only api_key.value secret dropped → inconsistent-result + import drift.
- Fix (provider branch fix/sp4-list-empty-marker-absence, issue #1099, PR #1100): renderUnmarshalListChild threads whenever stateBase!='' (drop container==single gate, both threadElem + null-preserve); empty-marker branch returns stateBase.Field for single AND list container (preserve absence); import-suppress 'standard' on APITesting+HTTPLoadBalancer. 3 new TDD + all SP3 tests intact; go test green; 128 regen+compile.
- LIVE VALIDATED: xcsh_api_testing + LB api_testing w/ api_key clear credential — apply idempotent (was inconsistent-result), round-trip import→exit2 write-only re-apply→clean. canonical restored 0-change, tenant clean.
- Also this cycle: cleaned orphaned api_testings (409 from earlier failed applies); ves-io-httplb-api-testing-* is LB-managed (403 direct delete, expected).
- REMAINING: #1100 CI→merge→auto-regen→release vX → bump webapp versions.tf → full api-testing-matrix (11 variants, SECRET+SKIP) all PASS/SKIP → whole-branch review → webapp PR Closes #45 → memory. Then SP5.

## 03:27 provider v3.71.4 RELEASED; SP4 full matrix running
- Provider chain COMPLETE: #1100 merged → auto-regen #1102 merged → **v3.71.4** published (14 assets, not draft). webapp versions.tf bumped >= 3.71.4 (committed). dev-override rebuilt from main.
- SP4 full api-testing-matrix (PID 96016, 11 variants: SECRET write-only-gate + SKIP blindfold) RUNNING with fixed binary. Smoke test already validated the fix (apply idempotent + round-trip import). Expect all PASS/SKIP.
- REMAINING: matrix all PASS/SKIP → fill sp4-findings table → whole-branch review → push sp4-api-testing → webapp PR Closes #45 → CI green → sync main → memory SP4 done → SP5 traffic-gen.

## 03:50 SP4 matrix GREEN (7 PASS/0 FAIL/4 SKIP); review dispatched
- api-testing-matrix with v3.71.4 dev-override: 7 PASS (all clear-secret credential arms both surfaces + canonical, via write-only re-apply gate) / 0 FAIL / 4 SKIP (blindfold=F5 XC 500, documented). sp4-findings.md table filled.
- Whole-branch review dispatched on sp4-api-testing diff (13 files +1068/-2). Then: address findings → push → webapp PR Closes #45 → CI → main → memory SP4 done.

## 04:08 SP4 COMPLETE ✅
- webapp PR #46 MERGED (issue #45 CLOSED), all CI green incl Lint Code Base (mypy cast fix + LB-empty-domains guard). provider issue #1099 CLOSED. provider v3.71.4 latest.
- Both mains synced (webapp 6824b43; provider main w/ #1100+#1102). Feature branches deleted. dev-override rebuilt from main. Memory updated (SP4 done → SP5).
- FINAL SP4: module both surfaces (real API contract), provider v3.71.4, live matrix 7 PASS/0 FAIL/4 SKIP. NEXT = SP5 API traffic-gen + behavioral verify.

## 04:47 SP5 API traffic-gen + behavioral verify — closed-loop PASS; PRs open
- User steer: NOT VPN-only, internet-exposed no-ACL, plan includes BOTH VMs (augmented traffic-gen + content server). Confirmed both VMs deployed (plan 0-change); LB serves HTTP (HTTPS 000 expected, no TLS); traffic-gen VM driving continuous load ~24 req/s.
- Suite (traffic-generator repo, PR #314 Closes #313): suites/api-protection-verify/{01-schema-violation,02-shadow-endpoints,03-protection-deny,04-rate-limit-burst}.sh — curl-based, UA sp5-api-verify, respects TARGET_PROTOCOL, auto-discovered by VM runner. shellcheck/shfmt clean.
- Harness (webapp, PR #48 Closes #47): scripts/api-protection-verify.sh — queries app_security/events with SERVER-SIDE req_path filter (flood-proof vs 500-cap + continuous-load svc_policy events).
- LIVE CLOSED-LOOP (webapp LB, restored): enabled api_protection deny + rate_limit → drove from traffic-gen VM (HTTP): POST /api/admin→403 blocked, burst→60/60×429 → harness confirmed **26 action=block events on /api/admin = PASS**. Canonical restored 0-change; both VMs left running.
- gotchas: VM run-command shell=sh (no pipefail); events limit cap 500; server-side query filter req_path="..." essential.
- REMAINING: #314 + #48 CI green→merge → sync mains → memory SP5 done (API effort SP1-5 COMPLETE).

## 04:52 SP5 COMPLETE ✅  — API EFFORT SP1–SP5 COMPLETE
- traffic-generator PR #314 (issue #313) + webapp PR #48 (issue #47) MERGED, all CI green. Both mains synced; branches deleted; temp cleaned. Memory updated (SP5 done, effort complete, no queued next).
- Full arc: SP1 discovery/crawler+SecretType (v3.71.2/#34/#36), SP2 definition+SCM (#38), SP3 protection (#42, provider v3.71.3), SP4 testing (#46, provider v3.71.4), SP5 traffic-gen+behavioral-verify (#48/#314). Provider v3.71.0→v3.71.4.
- Live env left healthy: canonical LB (features off, 0-change), both Azure VMs (content + augmented traffic-gen) running continuous load.

## 05:28 Coverage remediation — Batch A (validation enforcement) DONE pending review/PR
- Audit (2 agents) confirmed NOT-exhaustive coverage: 1 correctness bug (validation_all_spec_endpoints hardcoded skip_validation=enforces nothing) + documented YAGNI deferrals. User chose: close ALL gaps, batched, full TDD. 5 batches (A validation, B rate-limit, C sensitive-data, D matchers, E SCM).
- Batch A (branch batch-a-validation-enforcement, issue #49, commit 6266e56): parameterized full OpenAPI validation surface (request/response validation_mode skip|block|report + properties, settings oversized-body/additional-params, fall_through allow|custom) DRY across all_spec_endpoints+custom_list; de-hardcoded custom_list props; backfilled test_api_definition_pairs.py; fixed stale doc. 13 validation + 12 definition + 6 generator tests pass; defaults 0-change. LIVE-VERIFIED: all_spec_endpoints+block → validation_mode_active+enforcement_block on LB (was skip), idempotent + import-clean, NO provider change (v3.71.4 covers nested oneofs). Canonical restored.
- Pre-existing non-gate failure: apply.tftest (live command=apply) fails Healthcheck 404/AppFirewall 400 = namespace conflict w/ live LB; unrelated to Batch A, CI uses plan not full test.
- REMAINING: Batch A review→PR Closes #49→CI→merge; then Batches B,C,D,E.

## 05:35 Batch A PR #50 open (review fixes in); Batch B surface mapped
- Batch A review CLEAN (no Critical/Important); addressed 3 sub-threshold (response_properties SizeAtLeast guard, fall_through-custom precondition, faithful enforces output); 15 validation tests pass. PR #50 Closes #49, CI running.
- Batch B (rate limiting) SCHEMA MAPPED: LB rate_limit block (schema L19673): custom_ip_allowed_list|ip_allowed_list|no_ip_allowed_list + policies|no_policies + rate_limiter (currently module hardcodes no_ip_allowed_list+no_policies). LB api_rate_limit arm (L10923): api_endpoint_rules[] (ref_rate_limiter), bypass_rate_limiting_rules[], server_url_rules[]. Standalone xcsh_rate_limiter (limits[], user_identification[]) + xcsh_rate_limiter_policy. api_rate_limit + standalone rate_limiter are the deep object-graph deferred in SP3.
- REMAINING batches: B rate-limit (this surface), C sensitive-data (disclosure_rules + custom_data_types + xcsh_data_type), D matchers (server_url_rules + deep client_matcher asn/tls/selector), E SCM providers. Each: design→plan-TDD→live matrix→provider lock-step if needed→PR.

## 05:44 Batch A MERGED (PR #50, issue #49 closed, CI green). Starting Batch B.

## 09:51 HANDOFF checkpoint written for compact-resume
- docs/superpowers/HANDOFF-2026-07-15-coverage-batches-B-E.md + MEMORY.md pointer. Batch A merged; B–E scoped w/ schema anchors + per-batch rhythm + provider-lockstep + env gotchas. All repos on main, clean. Ready to /compact and resume Batch B (standalone xcsh_rate_limiter first).

## Batch B (rate limiting) — branch batch-b-rate-limiting, issue #51
- User steer: FULL client_matcher in B (not deferred to D). D then does api_protection_rules matchers + server_url_rules only.
- Stage 1 DONE: standalone xcsh_rate_limiter (variables_rate_limiter.tf + rate_limiter.tf + outputs; root passthrough). limits[] scalars + action(block action_block hours|minutes|seconds / disabled) + algorithm(leaky|token) + user_identification refs. unit=SECOND|MINUTE|HOUR (NO DAY). 9 plan-tests pass. LIVE: apply 1-add/0-change, idempotent, import round-trip (ns/name) 0-change. NO provider fix. Verify limiter "batch-b-rl-verify" LEFT in tenant for Stage 2/3 refs.
- Stage 2 (xcsh_rate_limiter_policy) module DONE: server scope (any_server|name_matcher|selector) + rules[] (metadata + action apply|bypass|custom + matchers asn/ip/country/http_method/path/domain/headers). 19 plan-tests pass. Contract facts: country codes MUST be COUNTRY_<ISO> enum (validated); a rule can AND multiple matchers; custom_rate_limiter is flat {name,namespace}. Optional list attrs emitted null-when-empty (F5 omits empty => plan [] vs read null drift). LIVE: apply idempotent after null-fix; IMPORT drift = server injects any_country on omitted country (any_ip already suppressed #1095; any_asn not injected on omit) + custom_rate_limiter.tenant cascade. FIX (batched provider release): suppress any_asn/any_country/any_ip for RateLimiterPolicy; removed module's explicit any options (omit=match any). Live policy batch-b-rlp-verify LEFT (re-verify after provider release).
- Stage 3 (LB rate_limit allow-lists/policies) DONE: ip_allowed_list|custom_ip_allowed_list|policies parameterized (replaces hardcoded no_ip/no_policies). Contract: inline rate_limiter total_number MAX 8192 (validated). LIVE apply+idempotent+LB-import CLEAN (object-ref policies/tenant round-trip fine, no HTTPLoadBalancer fix).
- Stage 4 (LB api_rate_limit arm) DONE: rate_limit_choice 3rd arm; api_endpoint_rules (path/domain/method + ref|inline limiter + full client_matcher + request_matcher cookie/header/jwt/query) + bypass_rate_limiting_rules + server_url_rules. 34 plan-tests total. Contract: bypass base_path is a url-oneof arm (target any_url|base_path|api_endpoint|api_groups; base_path dropped if sent with api_endpoint) — fixed module. LIVE apply+idempotent+LB-import CLEAN (any_client/any_ip already suppressed; server-injected request_matcher default handled). NO HTTPLoadBalancer provider fix.
- ONLY provider fix for Batch B = RateLimiterPolicy suppress any_country (server injects on omitted country; import drift) + defensively any_asn/any_ip. custom_rate_limiter.tenant drift = cascade of any_country (verify resolves after suppression).
- PROVIDER RELEASE: PR #1105 (Closes #1104) RateLimiterPolicy any_asn/any_country/any_ip suppression; TDD test added; go test/build green; verified LOCALLY via dev_overrides (policy import 0-change, tenant cascade resolved). CI running → auto-merge → auto-regen → release (monitoring). webapp pins >=3.71.4 (will bump to new ver).
- Canonical LB RESTORED (rate_limit=disable, test policy+limiter destroyed, 0-change). All 4 stages live-clean. 34 plan-tests. Whole-branch review dispatched.
- REMAINING: provider release done→bump webapp versions.tf→address review→webapp PR (Closes #51)→CI→merge→sync. Then Batch C.
- REVIEW (pr-review-toolkit) CLEAN on rendering (no Critical; oneofs value-switched, null-vs-[] consistent, single-knob, refs guarded, any-markers omitted). Addressed 2 Important (server_url inline_unit/inline_user_id validations; bypass+server_url client_matcher.mode validation) + Minor #3 (policy + all-3 client_matcher payload-non-empty guards), #4 (api_rate_limit arm requires >=1 rule precond), #5 (ip-allow-list off-arm precond), #6 (11 new negative tests). 45 plan-tests pass. Left reviewer's lookup() order-independence note (below bar, works today).

## Batch C (sensitive data) — branch batch-c-sensitive-data, issue #55
- xcsh_data_type (standalone): compliances/is_pii/is_sensitive_data (ALL Required — is_pii/is_sensitive default false, compliances always-set default []) + rules[] (key_pattern|value_pattern|key_value_pattern × regex|substring|exact). data_type.tf/variables_data_type.tf/outputs.
- sensitive_data_policy custom_data_types: single-knob refs (sensitive_data_custom_type_refs -> xcsh_data_type by name) + own lifecycle precondition (ref exists, avoids Invalid-index before LB precond).
- LB sensitive_data_disclosure_rules: sensitive_data_types_in_response[] (api_endpoint path/methods + body.fields + mask|report). Contract: body.fields min_items>=1 => omit body block when no fields (rule then = whole body). disabled_predefined test added.
- 13 plan-tests. LIVE: data_type + policy(custom_data_types) + LB disclosure apply->idempotent->import-clean ALL 3. NO provider change. Canonical restored 0-change.
- Fixed: coalesce(x,"") errors on empty => null-safe matcher validation. is_pii/is_sensitive_data/compliances Required on xcsh_data_type.

## Batch D (protection matchers) — branch batch-d-protection-matchers, issue #57
- CLEAN-BREAK: removed shared var.client_matcher (variables_client_matcher.tf/locals_client_matcher.tf/client_matcher_mode output). api_protection_rules now PER-RULE full client_matcher (any_ip/asn_list/asn_matcher/client_selector/ip_matcher/ip_prefix_list/ip_threat_category_list/tls_fingerprint_matcher) + request_matcher (cookie/header/jwt/query) + methods_invert (de-hardcoded).
- CORRECTION: api_protection_rules children = api_endpoint_rules + api_groups_rules (NOT server_url_rules — that's api_rate_limit's). Added api_protection_group_rules var (api_group|base_path + domain + action + client_matcher + request_matcher).
- Contract: tls_classes enum = TLS_FINGERPRINT_NONE|ANY_MALICIOUS_FINGERPRINT|ADWARE|ADWIND|DRIDEX|GOOTKIT|GOZI|JBIFROST|QUAKBOT|RANSOMWARE|TROLDESH|TOFSEE|TORRENTLOCKER|TRICKBOT (validated). api_groups_rules api_group must be a REAL discovered group (400 otherwise) — use base_path for self-contained; api_group live-SKIP. Updated api_protection.tftest.hcl (removed 4 shared-matcher runs). 21 api_protection plan-tests + 199 full plan-suite pass (only pre-existing apply.tftest live-apply fails).
- LIVE: api_protection_rules deep matchers (ip_threat/tls/ip_prefix/client_selector + request_matcher) + base_path api_groups_rules apply→idempotent→LB import CLEAN. NO provider change. Canonical restored 0-change.
- REMAINING: review→PR Closes #57→CI→merge; then Batch E (SCM providers).
- CI GOTCHA (Batch D): Lint Code Base has a JSCPD (copy-paste) gate, threshold 10%, and .jscpd.json is GOVERNANCE-LOCKED (can't edit; would need docs-control issue). Batch D's api_protection matcher render duplicating api_rate_limit's pushed HCL dup to 11.24%. FIX (real DRY, not masking): root passthrough vars for complex matcher-bearing surfaces → type=any (module is the single typed+validated contract). 11.24%→9.85%. Verified any→typed passthrough + canonical 0-change + module validations still fire. NOTE for Batch E: watch duplication; jscpd ignores yaml/workflows/internal-provider/docs but NOT terraform/ or scripts/.

## Batch E (SCM providers) — branch batch-e-scm-providers, issue #59, PR #60 [FINAL]
- xcsh_code_base_integration: github-only → 7 arms (github/github_enterprise/gitlab/gitlab_enterprise/azure_repos/bitbucket/bitbucket_server). provider selector + hostname/url/verify_ssl; token=access_token or passwd via clear/blindfold convention; per-arm preconditions. Renamed resource github→this (clean-break; fixed main.tf code-scan wiring + api-definition-matrix.sh).
- 14 plan-tests. LIVE: github arm apply→idempotent→import clean (write-only clear secret re-applies = expected). Other arms plan-tested (need real SCM endpoints). NO provider change. Canonical 0-change.
- JSCPD: scm.tf 7 secret blocks tipped dup to 10.58% → compact secret dynamic (local.scm_token_blindfold/_clear, one selector) dropped each block under clone threshold + thinned remaining complex root passthrough vars to type=any → 9.83%. codespell/shellcheck/shfmt clean. Review CLEAN (caught stale .github refs in main.tf + matrix script; both fixed).
- REMAINING: PR #60 CI→merge→sync. THEN: A–E EXHAUSTIVE COVERAGE COMPLETE.

## Batch F (app_api_group) — branch batch-f-app-api-group, issue #61
- Follow-on to live-verify Batch D api_groups_rules against a REAL api_group. Finding: named api_groups come from the app_api_group object (xcsh_app_api_group: elements path_regex/methods + http_loadbalancer assoc), NOT discovery alone (discovery=inventory). Added xcsh_app_api_group to module + wired api_protection_group_rules.api_group to reference it.
- Cycle avoidance: group refs LB by static local.lb_name (NOT the resource) + LB depends_on group → group created before LB validates api_groups_rules (F5 XC 400s on missing/unassociated group). 6 plan-tests.
- PROVIDER BUG FOUND + FIXED (lock-step): nested same-name single-block marshal shadowing — http_loadbalancer{http_loadbalancer{}} named both maps <GoName>Map, inner shadowed outer, outer sent empty {} → 400 (association dropped). Fix render.go subVar=childPath+"Map" (unique per depth). TDD TestRenderMarshalBlock_NestedSameNameNoShadow. PR #1109 (Closes #1108). Verified live via dev_overrides.
- LIVE (dev binary): group+rule apply (group first, no 400) → idempotent → group import 0-change → canonical restored. 
- REMAINING: provider release → bump webapp versions.tf → address review → webapp PR (Closes #61) → CI → merge.

## Batch G (secret-backend fields) — branch batch-g-blindfold-secret-backends, issue #63, PR #64
- Extended shared clear/blindfold SecretType convention (rendered_secret) with blindfold store_provider/decryption_provider + clear provider_ref, across crawler + 7 SCM arms. Optional, 0-change default. Validations: blindfold-only / clear-only. NO provider change (fields already in schema/marshalling; curl POST 200 confirms structure).
- 6 plan-tests. LIVE: clear provider_ref apply→idempotent→import (write-only re-apply expected). Blindfold live-apply = pre-existing XC-500 limit (fake sealed blob; real seal via blindfold-seal.sh) — documented, not a regression.
- BLOCKED ON GOVERNANCE: JSCPD 10.5%>10% (7 SCM secret blocks = inherent HCL dup; .jscpd.json governance-LOCKED). User chose docs-control path → issue f5-sales-demo/docs-control#645 (exempt scripts/*_pairs.py + terraform/modules/** OR raise threshold to 13, consistent w/ existing internal/provider exemption). PR #64 must NOT merge until #645 lands the .jscpd.json change (likely via sync-files propagation to webapp). Reverted speculative root-var thinnings to keep the PR focused.
- REMAINING: docs-control#645 resolves → .jscpd.json update propagates → PR #64 CI green → merge → sync. Review running.
