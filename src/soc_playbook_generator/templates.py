"""Markdown template loading and rendering."""

from __future__ import annotations

from pathlib import Path


DEFAULT_TEMPLATE = """# Playbook SOC - {incident_name}

**Entreprise :** {company}  
**Criticité :** {severity}  
**Version :** {version}

## 1. Résumé exécutif

- **Description courte :** {description}
- **Objectif du playbook :** {objective}
- **Niveau de criticité typique :** {default_severity}
- **Équipes concernées :**
{teams}

## 2. Contexte

**Description du scénario :** {scenario}

**Actifs potentiellement concernés :**
{assets}

**Sources de logs utiles :**
{log_sources}

**Hypothèses initiales :**
{assumptions}

## 3. Critères de qualification

**Éléments permettant de distinguer un faux positif d'un incident réel :**
{false_positive_clues}

**Indicateurs techniques à vérifier :**
{technical_indicators}

**Signaux faibles :**
{weak_signals}

**Critères d'escalade :**
{escalation_criteria}

## 4. Triage initial

**Questions à se poser :**
{triage_questions}

**Vérifications rapides :**
{quick_checks}

**Priorisation :**
- Prioriser les actifs critiques, les comptes privilégiés et les services exposés.
- Augmenter la criticité si l'impact métier, le nombre d'actifs ou la sensibilité des données augmente.
- Documenter toute décision avec horodatage, source de preuve et propriétaire de l'action.

**Décision possible :**
- Fermer si le faux positif est démontré et documenté.
- Surveiller si les signaux restent faibles mais non expliqués.
- Escalader si les critères d'escalade sont remplis.
- Traiter en incident si l'activité malveillante ou l'impact est confirmé.

## 5. Investigation technique

**Étapes détaillées d'analyse :**
{investigation_steps}

**Logs à consulter :**
{log_sources}

**Artefacts à récupérer :**
{artifacts}

**Requêtes SIEM génériques :**
{siem_queries}

**Points de vérification SOC :**
{control_checks}

## 6. Containment

**Actions immédiates de limitation :**
{containment_actions}

**Précautions avant action :**
{containment_precautions}

## 7. Remédiation

**Actions de remédiation :**
{remediation_actions}

**Vérification post-remédiation :**
{post_remediation_checks}

## 8. Preuves à collecter

{evidence}

## 9. Communication

**Qui prévenir :**
{notify}

**Message synthétique pour équipe technique :**
> {technical_message}

**Message synthétique pour management :**
> {management_message}

**Points à éviter dans la communication :**
{communication_avoid}

**Niveau de confidentialité :** {confidentiality}

## 10. Clôture et retour d'expérience

**Conditions de clôture :**
{closure_conditions}

**Vérifications finales :**
{final_checks}

**Leçons apprises :**
{lessons_learned}

**Amélioration des règles de détection :**
{detection_improvements}

**Amélioration du durcissement :**
{hardening_improvements}
"""


def load_template(template_path: str | Path | None = None) -> str:
    """Load a Markdown template from an explicit path, project root, or fallback."""
    candidates: list[Path] = []
    if template_path is not None:
        candidates.append(Path(template_path))

    package_file = Path(__file__).resolve()
    candidates.extend(
        [
            Path.cwd() / "templates" / "playbook_template.md",
            package_file.parents[2] / "templates" / "playbook_template.md",
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate.read_text(encoding="utf-8")

    return DEFAULT_TEMPLATE


def render_template(context: dict[str, str], template_path: str | Path | None = None) -> str:
    """Render a Markdown playbook from a context dictionary."""
    template = load_template(template_path)
    return template.format(**context).rstrip() + "\n"
