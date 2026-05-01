# SOC Playbook Generator

SOC Playbook Generator est un outil CLI Python qui génère des playbooks SOC opérationnels au format Markdown à partir d'un type d'incident de sécurité.

Le projet est pensé comme un portfolio cybersécurité professionnel : structure propre, code typé lorsque pertinent, templates Markdown, tests unitaires, contenu réaliste pour analystes SOC N1/N2, et aucune dépendance d'exécution inutile.

## Fonctionnalités

- Génération de playbooks Markdown complets dans `output/`
- Contenu spécifique par type d'incident, pas seulement un squelette générique
- CLI utilisable avec `python -m soc_playbook_generator`
- Liste des incidents supportés
- Personnalisation du nom d'entreprise et de la criticité
- Requêtes SIEM génériques : KQL, Lucene, pseudo-SQL, pivots par Event ID, IP, user, hostname ou hash
- Template Markdown modifiable dans `templates/playbook_template.md`
- Tests unitaires avec `pytest`

## Incidents supportés

- `ransomware`
- `phishing`
- `compromission_compte`
- `alerte_edr`
- `powershell_suspect`
- `fuite_donnees`
- `brute_force_vpn`

Des alias en français sont également acceptés, par exemple `compromission de compte`, `alerte edr`, `fuite de donnees` ou `brute force vpn`.

## Installation

Prérequis : Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Sans installation editable, depuis le dépôt :

```powershell
$env:PYTHONPATH = "src"
python -m soc_playbook_generator list
```

## Utilisation CLI

Lister les incidents disponibles :

```powershell
python -m soc_playbook_generator list
```

Générer un playbook ransomware :

```powershell
python -m soc_playbook_generator generate --incident ransomware
```

Le fichier généré sera écrit dans :

```text
output/playbook_ransomware.md
```

Générer un playbook personnalisé :

```powershell
python -m soc_playbook_generator generate --incident phishing --company "ACME" --severity high
```

Choisir un dossier de sortie :

```powershell
python -m soc_playbook_generator generate --incident "brute force vpn" --output-dir examples
```

Utiliser un template personnalisé :

```powershell
python -m soc_playbook_generator generate --incident alerte_edr --template templates/playbook_template.md
```

## Structure du projet

```text
soc-playbook-generator/
├── README.md
├── pyproject.toml
├── .gitignore
├── src/
│   └── soc_playbook_generator/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── generator.py
│       ├── incidents.py
│       ├── templates.py
│       └── utils.py
├── templates/
│   └── playbook_template.md
├── examples/
│   ├── ransomware_example.md
│   └── phishing_example.md
├── tests/
│   ├── conftest.py
│   ├── test_generator.py
│   └── test_cli.py
└── output/
```

## Sections générées

Chaque playbook contient :

1. Résumé exécutif
2. Contexte
3. Critères de qualification
4. Triage initial
5. Investigation technique
6. Containment
7. Remédiation
8. Preuves à collecter
9. Communication
10. Clôture et retour d'expérience

## Exemple de sortie

Extrait d'un playbook phishing :

````markdown
# Playbook SOC - Phishing

**Entreprise :** ACME
**Criticité :** high

## 5. Investigation technique

**Étapes détaillées d'analyse :**
1. Parser les en-têtes mail et identifier la chaîne de relais.
2. Comparer From, Reply-To, Return-Path et domaine d'authentification.
3. Rechercher emails similaires par sujet, expéditeur, URL et hash.

**Requêtes SIEM génériques :**
### KQL - recherche emails similaires

```text
EmailEvents
| where SenderFromAddress =~ "sender@example.com" or Subject has "urgent"
| join kind=leftouter EmailUrlInfo on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url
```
````

Des exemples complets sont disponibles dans `examples/`.

## Tests

```powershell
python -m pytest
```

Les tests couvrent :

- la génération de fichiers Markdown
- le rendu de contenu spécifique par incident
- les alias d'incidents
- la CLI `list`
- la CLI `generate`
- les erreurs d'incident inconnu ou de criticité invalide

## Philosophie SOC

Les playbooks ne remplacent pas les procédures internes, les exigences légales ou la décision du responsable incident. Ils fournissent une base structurée pour accélérer la qualification, l'investigation, le containment, la remédiation et le retour d'expérience.

Les requêtes SIEM sont volontairement génériques afin d'être adaptées à Microsoft Sentinel, Elastic, Splunk, QRadar ou à une plateforme interne.

## Licence

MIT.
