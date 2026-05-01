"""Playbook generation service."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .incidents import IncidentProfile, get_incident
from .templates import render_template
from .utils import ensure_directory, slugify, write_text_file

SUPPORTED_SEVERITIES = ("low", "medium", "high", "critical")


class UnknownIncidentError(ValueError):
    """Raised when a requested incident type is not supported."""


def _bullet_list(items: tuple[str, ...]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _numbered_list(items: tuple[str, ...]) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))


def _query_blocks(queries: tuple[tuple[str, str], ...]) -> str:
    blocks = []
    for title, query in queries:
        blocks.append(f"### {title}\n\n```text\n{query}\n```")
    return "\n\n".join(blocks)


def _validate_severity(severity: str) -> str:
    normalized = severity.strip().lower()
    if normalized not in SUPPORTED_SEVERITIES:
        allowed = ", ".join(SUPPORTED_SEVERITIES)
        raise ValueError(f"Criticité invalide '{severity}'. Valeurs autorisées: {allowed}.")
    return normalized


def resolve_incident(identifier: str) -> IncidentProfile:
    """Resolve an incident profile or raise a domain-specific error."""
    try:
        return get_incident(identifier)
    except KeyError as exc:
        raise UnknownIncidentError(f"Type d'incident non supporté: {identifier}") from exc


def build_context(profile: IncidentProfile, company: str, severity: str) -> dict[str, str]:
    """Build the string context consumed by the Markdown template."""
    raw = asdict(profile)
    context = {key: str(value) for key, value in raw.items() if isinstance(value, str)}
    context.update(
        {
            "company": company,
            "incident_name": profile.display_name,
            "severity": _validate_severity(severity),
            "version": "0.1.0",
            "teams": _bullet_list(profile.teams),
            "assets": _bullet_list(profile.assets),
            "log_sources": _bullet_list(profile.log_sources),
            "assumptions": _bullet_list(profile.assumptions),
            "false_positive_clues": _bullet_list(profile.false_positive_clues),
            "technical_indicators": _bullet_list(profile.technical_indicators),
            "weak_signals": _bullet_list(profile.weak_signals),
            "escalation_criteria": _bullet_list(profile.escalation_criteria),
            "triage_questions": _bullet_list(profile.triage_questions),
            "quick_checks": _bullet_list(profile.quick_checks),
            "investigation_steps": _numbered_list(profile.investigation_steps),
            "artifacts": _bullet_list(profile.artifacts),
            "siem_queries": _query_blocks(profile.siem_queries),
            "control_checks": _bullet_list(profile.control_checks),
            "containment_actions": _bullet_list(profile.containment_actions),
            "containment_precautions": _bullet_list(profile.containment_precautions),
            "remediation_actions": _bullet_list(profile.remediation_actions),
            "post_remediation_checks": _bullet_list(profile.post_remediation_checks),
            "evidence": _bullet_list(profile.evidence),
            "notify": _bullet_list(profile.notify),
            "communication_avoid": _bullet_list(profile.communication_avoid),
            "closure_conditions": _bullet_list(profile.closure_conditions),
            "final_checks": _bullet_list(profile.final_checks),
            "lessons_learned": _bullet_list(profile.lessons_learned),
            "detection_improvements": _bullet_list(profile.detection_improvements),
            "hardening_improvements": _bullet_list(profile.hardening_improvements),
        }
    )
    return context


def render_playbook(
    incident: str,
    company: str = "Organisation",
    severity: str | None = None,
    template_path: str | Path | None = None,
) -> str:
    """Render a playbook as Markdown without writing it to disk."""
    profile = resolve_incident(incident)
    selected_severity = severity or profile.default_severity
    context = build_context(profile, company=company, severity=selected_severity)
    return render_template(context, template_path=template_path)


def generate_playbook(
    incident: str,
    company: str = "Organisation",
    severity: str | None = None,
    output_dir: str | Path = "output",
    template_path: str | Path | None = None,
) -> Path:
    """Generate a Markdown playbook file and return its path."""
    profile = resolve_incident(incident)
    directory = ensure_directory(output_dir)
    destination = directory / f"playbook_{slugify(profile.key)}.md"
    content = render_playbook(
        profile.key,
        company=company,
        severity=severity or profile.default_severity,
        template_path=template_path,
    )
    return write_text_file(destination, content)
