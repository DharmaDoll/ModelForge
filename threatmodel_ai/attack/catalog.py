"""Small curated MITRE ATT&CK catalog used by deterministic MVP rules."""

from __future__ import annotations

from threatmodel_ai.attack.models import AttackTechnique

ATTACK_BASE_URL = "https://attack.mitre.org/techniques"


TECHNIQUES: dict[str, AttackTechnique] = {
    "T1190": AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactics=["Initial Access"],
        url=f"{ATTACK_BASE_URL}/T1190/",
    ),
    "T1499": AttackTechnique(
        id="T1499",
        name="Endpoint Denial of Service",
        tactics=["Impact"],
        url=f"{ATTACK_BASE_URL}/T1499/",
    ),
    "T1110": AttackTechnique(
        id="T1110",
        name="Brute Force",
        tactics=["Credential Access"],
        url=f"{ATTACK_BASE_URL}/T1110/",
    ),
    "T1078": AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        url=f"{ATTACK_BASE_URL}/T1078/",
    ),
    "T1557": AttackTechnique(
        id="T1557",
        name="Adversary-in-the-Middle",
        tactics=["Credential Access", "Collection"],
        url=f"{ATTACK_BASE_URL}/T1557/",
    ),
    "T1565": AttackTechnique(
        id="T1565",
        name="Data Manipulation",
        tactics=["Impact"],
        url=f"{ATTACK_BASE_URL}/T1565/",
    ),
    "T1552": AttackTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactics=["Credential Access"],
        url=f"{ATTACK_BASE_URL}/T1552/",
    ),
}
