"""Command-line interface for SOC Playbook Generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .generator import SUPPORTED_SEVERITIES, UnknownIncidentError, generate_playbook
from .incidents import list_incidents


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-playbook-generator",
        description="Génère des playbooks SOC opérationnels au format Markdown.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="Afficher les types d'incidents disponibles.")

    generate = subparsers.add_parser("generate", help="Générer un playbook Markdown.")
    generate.add_argument("--incident", required=True, help="Type d'incident à générer.")
    generate.add_argument("--company", default="Organisation", help="Nom de l'entreprise à intégrer au playbook.")
    generate.add_argument(
        "--severity",
        choices=SUPPORTED_SEVERITIES,
        help="Criticité à utiliser. Par défaut, la criticité typique de l'incident est utilisée.",
    )
    generate.add_argument("--output-dir", default="output", help="Dossier de sortie Markdown.")
    generate.add_argument("--template", help="Chemin optionnel vers un template Markdown personnalisé.")

    return parser


def _print_incidents() -> None:
    print("Types d'incidents disponibles:")
    for profile in list_incidents():
        aliases = ", ".join(profile.aliases)
        print(f"- {profile.key}: {profile.display_name} (aliases: {aliases})")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        _print_incidents()
        return 0

    if args.command == "generate":
        try:
            generated = generate_playbook(
                incident=args.incident,
                company=args.company,
                severity=args.severity,
                output_dir=Path(args.output_dir),
                template_path=args.template,
            )
        except UnknownIncidentError as exc:
            print(str(exc), file=sys.stderr)
            print("Utilisez 'python -m soc_playbook_generator list' pour voir les incidents supportés.", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        print(f"Playbook généré: {generated}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
