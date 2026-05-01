from __future__ import annotations

import pytest

from soc_playbook_generator.generator import UnknownIncidentError, generate_playbook, render_playbook
from soc_playbook_generator.incidents import list_incidents

TEST_OUTPUT = "test_output/generator"


def test_supported_incident_count() -> None:
    assert len(list_incidents()) == 7


def test_generate_ransomware_playbook_contains_specific_content() -> None:
    output = generate_playbook(
        "ransomware",
        company="ACME",
        severity="high",
        output_dir=TEST_OUTPUT,
    )

    content = output.read_text(encoding="utf-8")

    assert output.name == "playbook_ransomware.md"
    assert "**Entreprise :** ACME" in content
    assert "**Criticité :** high" in content
    assert "désactivation de sauvegardes" in content.lower() or "suppression de sauvegardes" in content.lower()
    assert "activité anormale SMB".lower() in content.lower() or "connexions SMB".lower() in content.lower()
    assert "KQL" in content
    assert "Lucene" in content
    assert "Pseudo-SQL" in content


def test_render_phishing_playbook_uses_phishing_context() -> None:
    content = render_playbook("phishing", company="Example Corp")

    assert "Playbook SOC - Phishing" in content
    assert "en-têtes" in content.lower()
    assert "URLs" in content
    assert "utilisateurs ayant clique" in content.lower() or "utilisateurs exposes" in content.lower()
    assert "mail gateway" in content.lower()


def test_incident_alias_with_accents_is_supported() -> None:
    output = generate_playbook("compromission de compte", output_dir=TEST_OUTPUT)

    assert output.name == "playbook_compromission_compte.md"
    assert "Compromission de compte" in output.read_text(encoding="utf-8")


def test_unknown_incident_raises_clear_error() -> None:
    with pytest.raises(UnknownIncidentError):
        render_playbook("incident inconnu")


def test_invalid_severity_is_rejected() -> None:
    with pytest.raises(ValueError, match="Criticité invalide"):
        render_playbook("phishing", severity="urgent")
