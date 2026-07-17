"""MITRE ATT&CK technique candidate generation."""

from threatmodel_ai.attack.engine import generate_attack_findings
from threatmodel_ai.attack.models import AttackFinding, AttackTechnique

__all__ = ["AttackFinding", "AttackTechnique", "generate_attack_findings"]
