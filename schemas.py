from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MessageRequest(StrictRequestModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)


class ExtractedIntelligence(BaseModel):
    upi_ids: List[str] = Field(default_factory=list)
    bank_accounts: List[str] = Field(default_factory=list)
    phishing_links: List[str] = Field(default_factory=list)


class ScamAnalysisResponse(BaseModel):
    is_scam: bool
    scam_type: Optional[str]
    extracted_intelligence: Optional[ExtractedIntelligence]
    confidence: float
    honeypot_reply: str
    risk: Optional[Dict[str, Any]] = None
    blocked: bool = False
    blocked_message: Optional[str] = None
    flagged_match: bool = False


class EmailAnalysisRequest(StrictRequestModel):
    message_id: Optional[str] = Field(default=None, max_length=128)
    thread_id: Optional[str] = Field(default=None, max_length=128)
    from_email: str = Field(min_length=3, max_length=320)
    from_name: Optional[str] = Field(default=None, max_length=256)
    subject: Optional[str] = Field(default=None, max_length=512)
    message_text: Optional[str] = Field(default=None, max_length=20000)
    links: List[str] = Field(default_factory=list, max_length=100)
    raw_headers: Optional[str] = Field(default=None, max_length=65_536)
    raw_eml: Optional[str] = Field(default=None, max_length=2_097_152)
    sender_ip: Optional[str] = Field(default=None, max_length=64)
    spf_result: Optional[str] = Field(default=None, max_length=32)
    dkim_result: Optional[str] = Field(default=None, max_length=32)
    dmarc_result: Optional[str] = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_message_source(self) -> "EmailAnalysisRequest":
        if not (self.message_text and self.message_text.strip()) and not self.raw_eml:
            raise ValueError("message_text or raw_eml is required.")
        return self


class AuthenticationResults(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    spf_domain: Optional[str] = None
    dkim_domain: Optional[str] = None
    aligned: Optional[bool] = None


class RelayHop(BaseModel):
    # Legacy fields (used by old header_analyzer)
    position: Optional[int] = None
    raw: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_private: bool = False
    is_trusted_relay: bool = False
    # New fields (used by new header_analyzer)
    hop_index: int = 0
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[Any] = None
    delay_seconds: Optional[float] = None


class HeaderAnalysis(BaseModel):
    from_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    message_id_domain: Optional[str] = None
    relay_hops: List[RelayHop] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)
    authentication: AuthenticationResults = Field(default_factory=AuthenticationResults)


class OriginTrace(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    confidence: float = 0.0


class DomainIntelResult(BaseModel):
    domain: Optional[str] = None
    is_lookalike: bool = False
    matched_brand: Optional[str] = None
    similarity: float = 0.0
    suspicious_tld: bool = False
    mx_records: List[str] = Field(default_factory=list)
    reputation_signals: List[str] = Field(default_factory=list)
    risk_signals: List[str] = Field(default_factory=list)


class BrandSpoofResult(BaseModel):
    suspected: bool = False
    display_name_match: bool = False
    domain_lookalike: bool = False
    authentication_failure: bool = False
    alignment_failure: bool = False
    matched_brand: Optional[str] = None


class EmailIndicator(BaseModel):
    key: str
    value: str


# --- New models for advanced email header analysis ---

class AuthProtocolResult(BaseModel):
    """Result of a single email authentication check (SPF, DKIM, or DMARC)."""
    status: str  # pass | fail | softfail | none | temperror | permerror
    domain: Optional[str] = None
    details: Optional[str] = None


class HeaderAnalysisResult(BaseModel):
    """Full result of email header forensic analysis."""
    relay_chain: List[RelayHop] = Field(default_factory=list)
    origin_ip: Optional[str] = None
    spf: AuthProtocolResult = Field(default_factory=lambda: AuthProtocolResult(status='none'))
    dkim: AuthProtocolResult = Field(default_factory=lambda: AuthProtocolResult(status='none'))
    dmarc: AuthProtocolResult = Field(default_factory=lambda: AuthProtocolResult(status='none'))
    anomalies: List[str] = Field(default_factory=list)
    is_spoofed: bool = False
    spoofing_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class EmailAnalysisResponse(BaseModel):
    is_scam: bool
    confidence: float
    risk: Dict[str, Any]
    scam_type: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    extracted_intelligence: Optional[ExtractedIntelligence] = None
    header_analysis: Optional[HeaderAnalysisResult] = None
    origin_trace: Optional[OriginTrace] = None
    domain_intel: Optional[DomainIntelResult] = None
    brand_spoof: Optional[BrandSpoofResult] = None


class Evidence(StrictRequestModel):
    """Structured evidence from a detector or telemetry event."""
    type: str = Field(description="Evidence type (e.g., 'text', 'entity', 'metric')", min_length=1, max_length=128)
    text: Optional[str] = Field(default=None, description="Text or value of the evidence", max_length=4096)
    source: Optional[str] = Field(default=None, description="Source of evidence (e.g., 'honeypot', 'detector')", max_length=128)


class TelemetryEvent(StrictRequestModel):
    """Telemetry event for swarm pheromone ingestion."""
    entity_type: str = Field(description="Entity type (e.g., 'ip', 'user', 'host', 'asset')", min_length=1, max_length=64)
    entity_id: str = Field(description="Unique identifier for the entity", min_length=1, max_length=512, pattern=r"^[a-zA-Z0-9.\-_@:]+$")
    score: float = Field(default=10, ge=0, le=100, description="Risk score 0-100")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence items", max_length=100)
    ts: Optional[float] = Field(default=None, description="Unix timestamp")


class JSONIngestRequest(RootModel[Dict[str, Any]]):
    @model_validator(mode="after")
    def validate_non_empty(self) -> "JSONIngestRequest":
        if not self.root:
            raise ValueError("Request body must be a non-empty JSON object.")
        return self


class SyslogIngestRequest(StrictRequestModel):
    raw: str | List[str]

    @model_validator(mode="after")
    def validate_raw(self) -> "SyslogIngestRequest":
        if isinstance(self.raw, str):
            if not self.raw.strip():
                raise ValueError("raw must not be empty.")
            return self
        if not self.raw:
            raise ValueError("raw must contain at least one syslog line.")
        if len(self.raw) > 100:
            raise ValueError("raw may contain at most 100 syslog lines per request.")
        if any(not str(line).strip() for line in self.raw):
            raise ValueError("raw may not contain empty syslog lines.")
        return self


class CSVIngestRequest(StrictRequestModel):
    csv: str = Field(min_length=1)
    column_map: Optional[Dict[str, str]] = None


class ActionRequest(StrictRequestModel):
    action: str = Field(min_length=1, max_length=128)
    actor: str = Field(default="api_user", min_length=1, max_length=128)
    params: Dict[str, Any] = Field(default_factory=dict)


class ContainmentActionRequest(StrictRequestModel):
    action: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=512, pattern=r"^[a-zA-Z0-9.\-_@:]+$")
    entity_type: str = Field(default="ip", min_length=1, max_length=64)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)
    reason: str = Field(default="", max_length=1024)
    incident_id: Optional[int] = None
    ttl_seconds: Optional[float] = Field(default=None, ge=0)


class PlaybookParamSpec(BaseModel):
    name: str
    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    required: bool = False
    description: Optional[str] = None
    default: Optional[Any] = None


class PlaybookAction(BaseModel):
    action: str
    description: str
    params: List[PlaybookParamSpec] = Field(default_factory=list)
    simulation_only: bool = True
    resolves_incident: bool = False
    status_on_success: Optional[str] = "mitigated"
    escalation_threshold: float = Field(default=70.0, ge=0, le=100)
    blast_radius_multiplier: float = Field(default=1.0, gt=0)


class PlaybookManifest(BaseModel):
    playbook_id: str
    name: str
    version: str = "1.0"
    actions: List[PlaybookAction] = Field(default_factory=list)


class PheromoneNode(BaseModel):
    """A node in the pheromone graph representing a network entity."""
    entity_id: str
    entity_type: str = Field(description="ip, user, host, domain, honeypot, conversation")
    total_pheromone: float = 0.0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PheromoneEdge(BaseModel):
    """An edge in the pheromone graph representing an observed relationship."""
    source: str
    target: str
    weight: float = 0.0
    signal_types: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    reinforcement_count: int = 0
    last_reinforced: Optional[float] = None


class GraphSnapshot(BaseModel):
    """Serializable snapshot of the pheromone graph for dashboard broadcast."""
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[float] = None


class AntStatus(BaseModel):
    """Status of an ant agent in the swarm."""
    ant_id: str
    ant_type: str = Field(description="scout, soldier, queen")
    state: str = Field(default="idle", description="idle, probing, investigating, reporting")
    current_entity: Optional[str] = None
    pheromones_deposited: int = 0
    anomalies_found: int = 0
    last_active: Optional[float] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class SwarmStatus(BaseModel):
    """Overall swarm health and metrics."""
    is_running: bool = False
    scout_count: int = 0
    soldier_count: int = 0
    queen_active: bool = False
    graph_stats: Dict[str, Any] = Field(default_factory=dict)
    active_investigations: int = 0
    total_pheromones_deposited: int = 0
    total_incidents_created: int = 0
    uptime_seconds: float = 0.0


class MitreMatch(BaseModel):
    """A matched MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic: Optional[str] = None
    similarity_score: float = Field(ge=0.0, le=1.0)
    description: Optional[str] = None


class AttackChain(BaseModel):
    """A linked sequence of ATT&CK techniques forming an attack path."""
    chain_id: str
    techniques: List[MitreMatch] = Field(default_factory=list)
    entities_involved: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    predicted_next: List[str] = Field(default_factory=list)
    timestamp: Optional[float] = None


class SimulationControl(StrictRequestModel):
    """Request to control the telemetry simulator."""
    action: Literal["start", "stop", "scenario"] = Field(description="start, stop, scenario")
    scenario: Optional[str] = Field(default=None, description="Scenario name for 'scenario' action", max_length=128)
    events_per_second: float = Field(default=2.0, ge=0.1, le=20.0)


class WSMessage(BaseModel):
    """WebSocket message format for real-time dashboard updates."""
    msg_type: str = Field(description="graph_update, incident, ant_activity, swarm_status, alert")
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[float] = None


