# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Criticality = Literal["low", "medium", "high", "critical"]


class TechniqueReference(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    technique_id: str = Field(alias="techniqueId")
    name: str
    expected_detection_sources: list[str] = Field(alias="expectedDetectionSources")
    criticality: Criticality

    @property
    def techniqueId(self) -> str:
        return self.technique_id

    @property
    def expectedDetectionSources(self) -> list[str]:
        return self.expected_detection_sources


TECHNIQUE_DETECTION_MAP: dict[str, TechniqueReference] = {
    "T1003": TechniqueReference(
        techniqueId="T1003",
        name="OS Credential Dumping",
        expectedDetectionSources=["EDR: credential access alert", "Windows Security: 4688", "Sigma: credential_dumping"],
        criticality="critical",
    ),
    "T1021": TechniqueReference(
        techniqueId="T1021",
        name="Remote Services",
        expectedDetectionSources=["Windows Security: 4624", "EDR: remote logon", "Sigma: lateral_movement_remote_services"],
        criticality="high",
    ),
    "T1041": TechniqueReference(
        techniqueId="T1041",
        name="Exfiltration Over C2 Channel",
        expectedDetectionSources=["Proxy: unusual egress", "EDR: data exfiltration", "Network IDS: C2 transfer"],
        criticality="critical",
    ),
    "T1047": TechniqueReference(
        techniqueId="T1047",
        name="Windows Management Instrumentation",
        expectedDetectionSources=["Windows Security: 4688", "Sysmon: Event ID 1", "Sigma: wmic_process_creation"],
        criticality="high",
    ),
    "T1053": TechniqueReference(
        techniqueId="T1053",
        name="Scheduled Task/Job",
        expectedDetectionSources=["Windows Security: 4698", "EDR: persistence", "Sigma: scheduled_task_creation"],
        criticality="high",
    ),
    "T1055": TechniqueReference(
        techniqueId="T1055",
        name="Process Injection",
        expectedDetectionSources=["EDR: process injection", "Sysmon: Event ID 8", "Sigma: process_injection"],
        criticality="critical",
    ),
    "T1059": TechniqueReference(
        techniqueId="T1059",
        name="Command and Scripting Interpreter",
        expectedDetectionSources=["EDR: process creation", "Sysmon: Event ID 1", "Sigma: suspicious_script_execution"],
        criticality="high",
    ),
    "T1071": TechniqueReference(
        techniqueId="T1071",
        name="Application Layer Protocol",
        expectedDetectionSources=["Proxy: beaconing", "DNS logs", "Network IDS: application-layer C2"],
        criticality="high",
    ),
    "T1078": TechniqueReference(
        techniqueId="T1078",
        name="Valid Accounts",
        expectedDetectionSources=["Windows Security: 4624", "IdP: anomalous sign-in", "EDR: suspicious authenticated activity"],
        criticality="critical",
    ),
    "T1087": TechniqueReference(
        techniqueId="T1087",
        name="Account Discovery",
        expectedDetectionSources=["Windows Security: 4688", "Directory audit logs", "Sigma: account_discovery"],
        criticality="medium",
    ),
    "T1105": TechniqueReference(
        techniqueId="T1105",
        name="Ingress Tool Transfer",
        expectedDetectionSources=["Proxy: download telemetry", "EDR: suspicious file write", "Sigma: ingress_tool_transfer"],
        criticality="high",
    ),
    "T1110": TechniqueReference(
        techniqueId="T1110",
        name="Brute Force",
        expectedDetectionSources=["IdP: failed login bursts", "Windows Security: 4625", "SIEM: password spraying"],
        criticality="high",
    ),
    "T1112": TechniqueReference(
        techniqueId="T1112",
        name="Modify Registry",
        expectedDetectionSources=["Sysmon: Event ID 13", "EDR: registry persistence", "Sigma: suspicious_registry_modification"],
        criticality="medium",
    ),
    "T1136": TechniqueReference(
        techniqueId="T1136",
        name="Create Account",
        expectedDetectionSources=["Windows Security: 4720", "Directory audit logs", "SIEM: privileged account creation"],
        criticality="high",
    ),
    "T1204": TechniqueReference(
        techniqueId="T1204",
        name="User Execution",
        expectedDetectionSources=["EDR: suspicious child process", "Email security: detonation", "Sigma: user_execution_payload"],
        criticality="medium",
    ),
    "T1486": TechniqueReference(
        techniqueId="T1486",
        name="Data Encrypted for Impact",
        expectedDetectionSources=["EDR: ransomware behavior", "File telemetry: mass modification", "Sigma: ransomware_indicators"],
        criticality="critical",
    ),
    "T1550": TechniqueReference(
        techniqueId="T1550",
        name="Use Alternate Authentication Material",
        expectedDetectionSources=["Windows Security: 4624", "EDR: pass-the-hash", "Sigma: alternate_auth_material"],
        criticality="critical",
    ),
    "T1562": TechniqueReference(
        techniqueId="T1562",
        name="Impair Defenses",
        expectedDetectionSources=["EDR: tamper protection", "Windows Security: 7036", "Sigma: defense_evasion_disable_security"],
        criticality="critical",
    ),
}
