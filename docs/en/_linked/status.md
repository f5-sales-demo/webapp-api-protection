---
title: Implementation status
slug: en/origin-traffic-remediation-tasks
sidebar:
  hidden: true
---


## Current snapshot: 2026-10-04

Umbrella: <https://github.com/f5-sales-demo/webapp-api-protection/issues/553>. Implementation: [origin issue
 #710](https://github.com/f5-sales-demo/origin-server/issues/710), [origin PR
 #711](https://github.com/f5-sales-demo/origin-server/pull/711), [traffic issue
 #711](https://github.com/f5-sales-demo/traffic-generator/issues/711), [traffic PR
 #713](https://github.com/f5-sales-demo/traffic-generator/pull/713), and [WAAP PR
 #554](https://github.com/f5-sales-demo/webapp-api-protection/pull/554). All PRs are drafts and all T01–T16
tasks remain incomplete.

This snapshot records the implementation revisions inspected before documentation reconciliation: origin `9dec3a1e0b18b35e13ceb0d9c71801152f34ae03`, generator `4c2f5287f52d01284418bc5c497d0eea058ead2c`, WAAP `8e13dc52d718fcce5c70bbdf888e375180b78ec3`. Documentation successors require their own CI/rendered build evidence. Full exact-head application and catalog qualification remains open.

The manifest declares nine prefixes and Compose declares 42 container services. The catalog retains 164
scenarios across 22 suites, including the stable 15 SQLi/18 XSS DVWA mappings. **Fourteen functional contracts
are declared; 150 scenarios have no declared functional contract. This count is not live qualification.** All
entries have execution contracts, which are separate from native functional acceptance.

| Evidence layer | Remaining gate |
| --- | --- |
| Source implementation | Recurring signup actor ownership, remaining complete functional contracts and interrupted mutation recovery |
| Installed verification | Complete exact-source nine-app matrix and all catalog functional contracts; benchmark/video remain unqualified |
| Rendered review | Complete final-source navigation/assets/forms/actors on every native and published serving layer |
| Final showcase | Merged upstream archives and installation, preservation reconciliation, clean rebuild, two accepted full passes, attributed controls, restart/reboot and zero-change repeat apply |

Private receipt identifiers include `private-browser-matrix-1791082428479897763`,
`manual-render-review-dc99bef.json`, `resume-native-followups/pass-focused-1791121335656328761/receipt.json`,
and `resume-native-functional-both-domains/pass-focused-1791079166467472534/receipt.json`. Each applies only
to its recorded candidate/scope. Failed login/schema, early screenshot, partial-plugin, dispatch-only,
transport, browser and CI receipts remain failed. Native application rejection does not prove WAAP mitigation.

The checked-in showcase profile/pins must be inspected together with private deployed receipts; variable
defaults alone are not installed provenance. CSD remains disabled (`csd_enabled=false`), with display-only
activity. Keep credentials, cloud IDs, state, mail, raw reports and screenshots private. Fresh full-head PII enforcement on the documentation candidate reported 86 findings outside docs: 43 Terraform,
35 test and eight script findings (61 identifier, 23 email and two home-path categories). Changed-document
enforcement/audit scans are clean. Full repository privacy qualification remains open; older findings and
failed scans remain preserved.

## Article comparison status

On 2026-10-05 UTC, historical baseline snapshots were relocated outside the active state
with verified hashes. Active Terraform state was unchanged. The exact deployed versioned
schema receipt was reconciled after source-byte and live-content verification, preserving
its predecessor. Backend, approved-scope, ownership and fixture preflight now pass.

The first controlled window completed request validation in 63.3 seconds: report mode returned
four 200s; block mode returned two 200s and two request-bound schema 403s. Both missing-field
and wrong-type events were verified, original configuration restored, protected readiness
passed and traffic restarted. Receipt `c5e52e4ad6494bed9f6d90033229f64b/schema` binds WAAP
`2d8980b`, origin `9dec3a1` and generator `4c2f528`.

The retry window `e1e964bf13494154891640263a7ea441` verified endpoint restrictions (88.3 seconds),
rate limiting (111.7 seconds) and authenticated DVWA SQL injection/reflected scripting
(78.9 seconds). Each category restored its original configuration; final protected readiness
passed and traffic restarted. The rate burst produced 23 origin 200 responses and seven
attributed 429s, with independent identity and unrelated path both successful. These results
bind WAAP `37327d3`, origin `9dec3a1` and generator `4c2f528`.

The focused malicious-user retry `a9fda1b5469a4afd906edabd3ab64fd2/mud` completed in
116.9 seconds on WAAP `11f1cf8`, origin `9dec3a1` and generator `4c2f528`. It verified fresh
suspicious-user detection before a later benign-request temporary block, with an independent
identity successful. Each of 23 requests per phase joined to an actual access record.
Configuration restored; final window readiness and traffic restart are recorded separately.
All five representative categories now have matched configuration/request evidence. Earlier
incomplete receipts remain failed; these results do not qualify the full catalog or bypass
merged-installation, clean-rebuild, privacy and final acceptance gates.

## Implementation tasks

All tasks remain incomplete. The linked issues and PRs above own their detailed acceptance contracts.

| Task | Remaining gate |
| --- | --- |
| T01 — Record baseline | Reconcile preservation baseline |
| T02 — Application manifest | Verify final landing/output inventory |
| T03 — Coverage matrix | Finish functional/fixture matrix |
| T04 — Unified provisioning | Install merged archives in both roots |
| T05 — Prefix handling | Verify final prefix routing after rebuild |
| T06 — Application defects | Complete current nine-app matrix |
| T07 — DVWA payload coverage | Qualify all 33 preserved payloads |
| T08 — Repeatable fixtures | Prove interruption recovery |
| T09 — Content verifier | Review final-source screenshots |
| T10 — Serving layers | Verify all final serving layers |
| T11 — Scenario receipts | Complete all native functional contracts |
| T12 — Outcome attribution | Correlate each required control |
| T13 — Lifecycle integration | Verify merged startup/readiness |
| T14 — Repair loop | Close current source/CI/live repairs |
| T15 — Clean rebuild | Prove owned absence/preservation/recreate |
| T16 — Final acceptance | Two accepted passes; recovery and zero drift |

### Task acceptance details

#### T01: Record baseline

Status: In progress. Dependencies: none.

Capture routes, replicas, fixtures, rendered failures, catalog, deployed digests, Terraform ownership and shared identities; retain private receipt.

#### T02: Application manifest

Status: In progress. Dependencies: T01.

Exactly nine applications reconciled across declaration, docs, landing, outputs and traffic.

#### T03: Coverage matrix

Status: In progress. Dependencies: T02.

Native/published routes, replicas, assertions, fixtures and scenarios; no missing/orphan entries.

#### T04: Unified provisioning

Status: In progress. Dependencies: T02.

Both roots consume one immutable origin installer including existing pinned dependencies and repairs.

#### T05: Prefix handling

Status: In progress. Dependencies: T04.

Assets, links, forms, API, redirects, cookies and SPA routes retain application prefixes.

#### T06: Application defects

Status: In progress. Dependencies: T05.

All nine applications pass specified authenticated/seeded/rendered workflows and replica checks.

#### T07: DVWA payload coverage

Status: Open. Dependencies: T03,T08.

All 15 SQLi and 18 XSS payloads reach authenticated DVWA; preserve stable scenario ID mappings.

#### T08: Repeatable fixtures

Status: In progress. Dependencies: T04.

Synthetic fixture reruns produce no duplicates; scoped mutations restored; blocked setup cannot suppress launches.

#### T09: Content verifier

Status: In progress. Dependencies: T03.

Landing reconciliation, navigation, rendered assets/images, console/network, forms and authentication fail closed; screenshots reviewed.

#### T10: Serving layers

Status: In progress. Dependencies: T06,T09.

All native replicas, origin nginx, both domains HTTP/HTTPS; identity/type correct; wrong-content 200 fails.

#### T11: Scenario receipts

Status: In progress. Dependencies: T03,T07.

164 entries across 22 suites; intended method/path/payload and browser/connection action observed apart from setup/filler.

#### T12: Outcome attribution

Status: In progress. Dependencies: T11.

Explicit negative cases; mitigation, rejection, fixture/tool/transport failure and timeout distinguished.

#### T13: Lifecycle integration

Status: In progress. Dependencies: T04,T08,T10,T12.

Existing lifecycle/control verbs preserved; immutable inputs/digests/URL maps recorded; startup gated on complete readiness.

#### T14: Repair loop

Status: In progress. Dependencies: T13.

Source checks, installed and live gates pass on committed immutable configuration; failed receipts retained.

#### T15: Clean rebuild

Status: Open. Dependencies: T14.

One ownership-checked destroy/absence/preservation/recreate from committed source; no manual fixture setup.

#### T16: Final acceptance

Status: Open. Dependencies: T15.

Two complete catalog passes; 200 aggregate RPS within 5%; 180 benign equally split/rotated across nine apps; >=99% success, zero transport failures; attributed controls; stop/restart/reboot; unchanged apply then zero plan; continuous service running.

Detailed candidate receipts and historical failures remain in the [implementation archive](../archive/origin-traffic-remediation-history/).

## Delivery dependencies

Complete upstream implementation gates before merging origin #711 and generator #713. Pin their merged commits
and archive/installer digests in WAAP, prove installed provenance, then complete T15/T16 before merging WAAP
 #554. Required CI, documentation rendering and human showcase acceptance are separate gates. After each merge,
verify Pages publication from that merged revision and published navigation/LLM links.

[Historical archive](../archive/origin-traffic-remediation-history/) preserves the original tracker entries,
including dated failures and narrower successful candidates. It is evidence history, not current acceptance.
[Demo guide](../demo/) documents lifecycle and preservation; [traffic
tracker](https://f5-sales-demo.github.io/traffic-generator/en/continuous-catalog-tasks/) records upstream
outstanding work.

[LLM discovery](../llm-discovery/) links the source-generated text hierarchy.
