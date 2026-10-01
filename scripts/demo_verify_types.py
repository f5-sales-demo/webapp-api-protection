"""Verifier evidence contracts; opaque input is not validated or public proof.

Report schemas contain only the existing verifier's allowlisted summaries.
Private manifest and output schemas describe inputs, not permission to publish
resource identifiers, addresses, upstream payloads, or human identities.
"""

from dataclasses import dataclass
from typing import Any, Literal, NotRequired, Protocol, TypedDict

# Preserve the existing verifier CLI statuses, including failure being two.
VERIFIED = 0
FAILURE = 2
PENDING = 3


class EvidenceError(Exception):
    """Safe error containing no upstream strings or credential material."""


class DenialRequest(TypedDict):
    """One observed denial within the bounded rate burst."""

    request: int
    sent_at: float


class Probe(TypedDict):
    """Fresh synthetic request joined to independently observed telemetry."""

    host: str
    path: str
    method: str
    user: str
    sent_at: float
    control: str
    attack_started_at: NotRequired[float]
    mitigation_sent_at: NotRequired[float]
    mitigation_blocked: NotRequired[bool]
    status: NotRequired[int]
    burst_end: NotRequired[float]
    denial_requests: NotRequired[list[DenialRequest]]


class Vm(TypedDict):
    """Private guest connection inputs used by the verifier."""

    public_ip: str
    admin_username: str
    id: NotRequired[str]


class ShowcaseOutputs(TypedDict):
    """Private showcase outputs whose protection values require validation."""

    namespace: str
    loadbalancer_name: str
    domains: list[str]
    origin: Vm
    generator: Vm
    protection: dict[str, Any]


class VerifyOptions(Protocol):
    """Options consumed by readiness and acceptance evidence collection."""

    poll_seconds: float
    ssh_key: str | None
    known_hosts: str | None


class EvidenceReader(Protocol):
    """Read exact captured identities without granting mutation authority."""

    def api(self, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
        """Read API evidence, retaining opaque wire payloads until validation.

        Args:
            path: Exact scoped API path.
            payload: Optional documented read-query body.

        Returns:
            HTTP status and unvalidated decoded JSON.
        """

    def azure_exists(self, sub: str, resource_id: str, api_version: str) -> bool:
        """Check an exact ARM resource using its captured provider version.

        Args:
            sub: Privately approved subscription identifier.
            resource_id: Exact captured resource identifier.
            api_version: Captured provider API version.

        Returns:
            Whether the exact identity exists; transport failure must raise.
        """


@dataclass(frozen=True)
class CheckedAzure:
    """Validated private ARM identity and required presence expectation."""

    sub: str
    resource_id: str
    api_version: str
    present: bool


@dataclass(frozen=True)
class CheckedXC:
    """Validated private XC identity and required presence expectation."""

    path: str
    uid: str
    present: bool


@dataclass(frozen=True)
class CheckedManifest:
    """Validated exact identity checks, never an adoption or ownership grant."""

    azure: tuple[CheckedAzure, ...]
    xc: tuple[CheckedXC, ...]


class XCIdentity(TypedDict):
    """Private captured XC identity in the existing absence manifest."""

    path: str
    uid: str


class RunManifest(TypedDict):
    """Private version-one absence receipt requiring runtime scope validation."""

    schema_version: int
    subscription_id: str
    azure_owned: list[str]
    xc_owned: list[XCIdentity]
    azure_preserved: list[str]
    xc_preserved: list[XCIdentity]
    azure_api_versions: dict[str, str]


class TrafficFailure(TypedDict):
    """Allowlisted fresh terminal scheduled-traffic failure summary."""

    run_id: str
    error_class: str
    metric_failures: list[str]


class CloudDiagnostic(TypedDict):
    """Sanitized cloud-init result; warning text never enters this schema."""

    status: str
    fatal_errors: int
    warnings_accepted: int
    reason: NotRequired[str]
    sources: NotRequired[list[str]]
    final_unit_success: NotRequired[bool]


class ProbeResult(TypedDict):
    """Whitelisted response status, without raw response bodies or users."""

    control: str
    status: int


class RateBurstSummary(TypedDict):
    """Bounded rate evidence, including partial sanitized failure diagnostics."""

    control: str
    host: str
    request_limit: int
    duration_budget_seconds: float
    threshold: int
    unit: str
    identity: str
    status_counts: dict[str, int]
    bucket_semantics: str
    bucket_semantics_source: str
    rate_proof_source: str
    request_count: NotRequired[int]
    duration_seconds: NotRequired[float]
    denial_count: NotRequired[int]
    first_denial_request: NotRequired[int]
    independent_user_allowed: NotRequired[bool]
    same_user_unrelated_path_allowed: NotRequired[bool]
    attributed_event_count: NotRequired[int]
    diagnostic: NotRequired[str]


class TrafficRunSummary(TypedDict):
    """Existing report projection of a verified scheduled traffic run."""

    run_id: str
    count: int
    rate: float
    duration_seconds: float
    latencies: dict[str, int | float]
    transport_errors: int
    benign_success: float
    class_counts: dict[str, int]
    rate_outcomes: dict[str, dict[str, Any]]
    security_evidence_scope: str


class AcceptanceEvidence(TypedDict):
    """Independent control and traffic gates, not inferred from configuration."""

    run_id: str
    probe_count: int
    controls_attributed: bool
    scheduled_traffic: bool
    mud_detection: bool
    mud_mitigation: bool
    suspicious_log_count: int
    rate_bursts: list[RateBurstSummary]
    traffic_failure: NotRequired[TrafficFailure]
    failure: NotRequired[str]
    traffic_runs: NotRequired[list[TrafficRunSummary]]
    pending: NotRequired[str]


class ReadinessEvidence(TypedDict):
    """Effective controls, guest readiness and live application observations."""

    effective_controls: bool
    cloud_init: bool
    cloud_init_info: dict[str, CloudDiagnostic]
    origin_checks: int
    application_domains: int


class ReadRetry(TypedDict):
    """Sanitized read-only retry diagnostic with no upstream identifiers."""

    reason: str
    attempt: int


class VerificationReport(TypedDict):
    """Existing version-one public report, built before collection begins."""

    schema_version: int
    phase: Literal["readiness", "acceptance", "absence"]
    verified: bool
    sources: list[str]
    evidence: NotRequired[ReadinessEvidence | AcceptanceEvidence]
    failure: NotRequired[str]
    read_retries: NotRequired[list[ReadRetry]]
    exit_code: NotRequired[int]
