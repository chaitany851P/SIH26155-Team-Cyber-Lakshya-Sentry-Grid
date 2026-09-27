from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class AuditMetadata(BaseModel):
    audit_id: str
    timestamp: str
    schema_version: str = "1.0.0"
    hash_algorithm: str = "SHA-512"
    cryptographic_seal: str


class DeviceInfoModel(BaseModel):
    hostname: str
    vendor: str
    os_family: str
    os_version: str
    model: str
    serial_number: str
    raw_config_sha512: str


class AAABaseline(BaseModel):
    password_encryption_enabled: bool = False
    min_password_length: int = 8
    session_timeout_minutes: int = 0
    external_auth_configured: bool = False


class ManagementAccessBaseline(BaseModel):
    ssh_enabled: bool = True
    ssh_version: int = 2
    telnet_disabled: bool = True
    http_server_disabled: bool = True
    https_server_enabled: bool = True


class LoggingAuditBaseline(BaseModel):
    syslog_servers: List[str] = Field(default_factory=list)
    audit_trail_enabled: bool = True


class TimeSyncBaseline(BaseModel):
    ntp_servers: List[str] = Field(default_factory=list)
    timezone: str = "UTC"


class NormalizedBaselineModel(BaseModel):
    aaa: AAABaseline = Field(default_factory=AAABaseline)
    management_access: ManagementAccessBaseline = Field(default_factory=ManagementAccessBaseline)
    logging_audit: LoggingAuditBaseline = Field(default_factory=LoggingAuditBaseline)
    time_synchronization: TimeSyncBaseline = Field(default_factory=TimeSyncBaseline)


class ComplianceFindingModel(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    control_reference: str
    severity: str
    status: str
    found_value: str
    expected_value: str
    mitre_technique: Optional[str] = None
    remediation_cli: str
    rollback_cli: str


class ComplianceSummaryModel(BaseModel):
    total_rules_evaluated: int
    passed_count: int
    failed_count: int
    overall_compliance_percentage: float
    risk_level: str


class FormalProofModel(BaseModel):
    formal_status: str
    smt_engine: str
    proof_type: str
    model_satisfied: bool
    counterexample: Optional[List[str]] = None
    explanation: str


class CanonicalAuditRecord(BaseModel):
    metadata: AuditMetadata
    device_info: DeviceInfoModel
    normalized_baseline: NormalizedBaselineModel
    findings: List[ComplianceFindingModel]
    summary: ComplianceSummaryModel
    formal_proof: FormalProofModel
