from __future__ import annotations

from pathlib import Path

from soc_playbook_generator.cli import main

TEST_OUTPUT = "test_output/cli"


def test_cli_list_displays_supported_incidents(capsys) -> None:
    exit_code = main(["list"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "ransomware" in captured.out
    assert "phishing" in captured.out
    assert "brute_force_vpn" in captured.out


def test_cli_generate_creates_markdown_file(capsys) -> None:
    exit_code = main(
        [
            "generate",
            "--incident",
            "phishing",
            "--company",
            "ACME",
            "--severity",
            "high",
            "--output-dir",
            TEST_OUTPUT,
        ]
    )

    captured = capsys.readouterr()
    generated = Path(TEST_OUTPUT) / "playbook_phishing.md"

    assert exit_code == 0
    assert "Playbook généré" in captured.out
    assert generated.exists()
    assert "**Entreprise :** ACME" in generated.read_text(encoding="utf-8")


def test_cli_unknown_incident_returns_error(capsys) -> None:
    exit_code = main(["generate", "--incident", "not-a-real-incident"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Type d'incident non supporté" in captured.err
    assert "list" in captured.err
