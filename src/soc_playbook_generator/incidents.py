"""Incident profiles used to render SOC playbooks."""

from __future__ import annotations

from dataclasses import dataclass

from .utils import normalize_key


@dataclass(frozen=True)
class IncidentProfile:
    key: str
    display_name: str
    aliases: tuple[str, ...]
    description: str
    objective: str
    default_severity: str
    teams: tuple[str, ...]
    scenario: str
    assets: tuple[str, ...]
    log_sources: tuple[str, ...]
    assumptions: tuple[str, ...]
    false_positive_clues: tuple[str, ...]
    technical_indicators: tuple[str, ...]
    weak_signals: tuple[str, ...]
    escalation_criteria: tuple[str, ...]
    triage_questions: tuple[str, ...]
    quick_checks: tuple[str, ...]
    investigation_steps: tuple[str, ...]
    artifacts: tuple[str, ...]
    siem_queries: tuple[tuple[str, str], ...]
    control_checks: tuple[str, ...]
    containment_actions: tuple[str, ...]
    containment_precautions: tuple[str, ...]
    remediation_actions: tuple[str, ...]
    post_remediation_checks: tuple[str, ...]
    evidence: tuple[str, ...]
    notify: tuple[str, ...]
    technical_message: str
    management_message: str
    communication_avoid: tuple[str, ...]
    confidentiality: str
    closure_conditions: tuple[str, ...]
    final_checks: tuple[str, ...]
    lessons_learned: tuple[str, ...]
    detection_improvements: tuple[str, ...]
    hardening_improvements: tuple[str, ...]


def profile(
    key: str,
    display_name: str,
    aliases: tuple[str, ...],
    description: str,
    objective: str,
    default_severity: str,
    indicators: tuple[str, ...],
    investigation_steps: tuple[str, ...],
    siem_queries: tuple[tuple[str, str], ...],
    containment_actions: tuple[str, ...],
    remediation_actions: tuple[str, ...],
    evidence: tuple[str, ...],
    log_sources: tuple[str, ...],
    scenario: str,
) -> IncidentProfile:
    return IncidentProfile(
        key=key,
        display_name=display_name,
        aliases=aliases,
        description=description,
        objective=objective,
        default_severity=default_severity,
        teams=("SOC N1/N2", "CSIRT", "Equipe infrastructure", "RSSI"),
        scenario=scenario,
        assets=("Postes utilisateurs", "Serveurs", "Comptes", "Applications metier", "Services exposes"),
        log_sources=log_sources,
        assumptions=(
            "L'alerte doit etre qualifiee avec des preuves horodatees.",
            "Le perimetre peut evoluer pendant l'investigation.",
            "Les actions de containment doivent preserver les preuves utiles.",
        ),
        false_positive_clues=(
            "Action planifiee ou changement approuve par une equipe technique.",
            "Outil legitime connu, signe et coherent avec l'inventaire.",
            "Evenement isole sans recurrence ni indicateur associe.",
        ),
        technical_indicators=indicators,
        weak_signals=(
            "Activite hors horaires habituels.",
            "Compte, IP ou hostname rarement observe.",
            "Changement de comportement juste avant ou apres l'alerte.",
        ),
        escalation_criteria=(
            "Actif critique ou compte privilegie implique.",
            "Indicateur malveillant confirme.",
            "Propagation, exfiltration ou impact metier suspecte.",
        ),
        triage_questions=(
            "Quel est le premier evenement connu ?",
            "Quels utilisateurs, hotes et IP sont concernes ?",
            "L'activite est-elle encore en cours ?",
            "Quel est l'impact metier potentiel ?",
        ),
        quick_checks=(
            "Verifier la timeline SIEM/EDR des dernieres heures.",
            "Comparer avec l'historique de l'utilisateur et du hostname.",
            "Pivoter sur IP, user, hostname, hash, domaine et Event ID.",
        ),
        investigation_steps=investigation_steps,
        artifacts=("Exports SIEM", "Timeline EDR", "Logs bruts", "Hash", "Hostname", "Utilisateur", "IP source/destination"),
        siem_queries=siem_queries,
        control_checks=(
            "EDR: timeline, processus parent/enfant, hash et reputation.",
            "Firewall/proxy: connexions sortantes, URL et volumes.",
            "Mail gateway: messages similaires, pieces jointes et liens.",
            "AD/IAM/VPN: authentifications, MFA, groupes et sessions.",
            "DNS: domaines resolus et destinations rares.",
        ),
        containment_actions=containment_actions,
        containment_precautions=(
            "Valider l'impact metier avant coupure large.",
            "Conserver les preuves avant suppression ou reinstallation.",
            "Tracer chaque action avec horodatage, auteur et justification.",
        ),
        remediation_actions=remediation_actions,
        post_remediation_checks=(
            "Relancer les recherches sur les indicateurs.",
            "Confirmer l'absence de nouvelle activite suspecte.",
            "Valider avec le proprietaire metier que le service est sain.",
        ),
        evidence=evidence,
        notify=("SOC lead", "CSIRT", "Equipe technique concernee", "RSSI", "Responsable metier si impact"),
        technical_message=f"Incident {display_name} en qualification. Merci de conserver les journaux, verifier les indicateurs et appliquer les actions validees.",
        management_message=f"Un incident de type {display_name} est en cours d'analyse. Les equipes securite evaluent le perimetre, l'impact et les mesures de limitation.",
        communication_avoid=(
            "Ne pas conclure avant validation par preuves.",
            "Ne pas diffuser d'indicateurs sensibles hors canal approuve.",
            "Ne pas supprimer de preuve avant collecte.",
        ),
        confidentiality="Confidentiel securite - diffusion limitee aux equipes autorisees.",
        closure_conditions=(
            "Perimetre qualifie et documente.",
            "Containment et remediation termines ou risque residuel accepte.",
            "Surveillance post-incident active.",
        ),
        final_checks=(
            "Recherche retrospective sur 7 a 30 jours.",
            "Validation EDR/SIEM sur les indicateurs.",
            "Confirmation de cloture par le responsable incident.",
        ),
        lessons_learned=(
            "Identifier le vecteur initial et les controles manquants.",
            "Evaluer le delai de detection et de reaction.",
            "Documenter les obstacles rencontres pendant l'investigation.",
        ),
        detection_improvements=(
            "Ajouter ou ajuster les regles de correlation SIEM.",
            "Ameliorer les seuils et la qualite du contexte d'alerte.",
            "Creer des pivots sur user, IP, hostname, hash et domaine.",
        ),
        hardening_improvements=(
            "Appliquer le moindre privilege.",
            "Renforcer MFA, journalisation et segmentation.",
            "Revoir les configurations exposees ou les exceptions securite.",
        ),
    )


INCIDENTS: dict[str, IncidentProfile] = {
    "ransomware": profile(
        "ransomware",
        "Ransomware",
        ("rancongiciel", "ransomware"),
        "Suspicion de chiffrement malveillant, d'extorsion ou de preparation ransomware.",
        "Qualifier l'etendue, contenir la propagation, preserver les preuves et guider la restauration.",
        "critical",
        (
            "Chiffrement massif ou renommage rapide de fichiers.",
            "Extensions suspectes et creation de README ransom.",
            "Connexions SMB nombreuses vers plusieurs hotes.",
            "Suppression ou desactivation de sauvegardes via vssadmin, wbadmin ou bcdedit.",
            "Processus inconnu execute depuis Temp, AppData ou partage reseau.",
        ),
        (
            "Identifier le patient zero, le processus parent et la commande.",
            "Rechercher les extensions suspectes, notes de rancon et hash sur le parc.",
            "Verifier activite SMB, RDP, WMI, PsExec, WinRM et suppression de shadow copies.",
            "Controler proxy, DNS et firewall pour une exfiltration prealable.",
        ),
        (
            ("KQL - chiffrement massif", 'DeviceFileEvents\n| where FileName has_any ("README", "RECOVER", "DECRYPT") or PreviousFileName != ""\n| summarize count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)'),
            ("Lucene - ransomware", 'event.category:file AND (file.name:*README* OR process.name:(vssadmin.exe wbadmin.exe bcdedit.exe))'),
            ("Pseudo-SQL - volume fichiers", "SELECT hostname, user, process_name, COUNT(*) FROM file_events WHERE action IN ('rename','modify','delete') GROUP BY hostname, user, process_name HAVING COUNT(*) > 500;"),
            ("Windows Event ID", "4688 pour processus, Sysmon 1/3, 5140/5145 pour SMB."),
        ),
        ("Isoler immediatement les machines suspectes.", "Bloquer hash, domaines et IP.", "Couper les partages SMB non essentiels si propagation active.", "Proteger les sauvegardes."),
        ("Supprimer binaire et persistence.", "Corriger le vecteur initial.", "Reinitialiser comptes impliques.", "Restaurer depuis sauvegardes verifiees."),
        ("Fichiers chiffres", "Note de rancon", "Hash", "Processus", "Connexions SMB", "Exports SIEM/EDR"),
        ("EDR/XDR", "SIEM", "Windows Security", "Sysmon", "Fileserver audit", "Firewall", "DNS", "Sauvegardes"),
        "Un hote presente des signes de chiffrement, note de rancon ou activite SMB anormale.",
    ),
    "phishing": profile(
        "phishing",
        "Phishing",
        ("phishing", "hameconnage", "mail frauduleux", "email suspect"),
        "Email suspect visant a voler des identifiants, executer une piece jointe ou rediriger vers une page malveillante.",
        "Qualifier la campagne, identifier les utilisateurs exposes et bloquer les elements malveillants.",
        "medium",
        ("En-têtes SPF/DKIM/DMARC en echec.", "URLs suspectes ou domaine lookalike.", "Pieces jointes HTML, macro ou archive.", "Expediteur usurpe ou Reply-To incoherent.", "Utilisateurs ayant clique ou saisi des identifiants."),
        ("Analyser les en-têtes mail complets.", "Extraire URLs, pieces jointes et hash.", "Rechercher emails similaires par sujet, expediteur, URL et Message-ID.", "Croiser avec proxy, DNS, EDR et IAM pour les clics et connexions."),
        (
            ("KQL - emails similaires", 'EmailEvents\n| where SenderFromAddress =~ "sender@example.com" or Subject has "urgent"\n| join kind=leftouter EmailUrlInfo on NetworkMessageId'),
            ("Lucene - clics proxy", 'url.domain:(example-login.com OR bit.ly) OR url.full:*credential*'),
            ("Pseudo-SQL - destinataires", "SELECT recipient, subject, url FROM mail_events WHERE sender_domain = 'suspicious.example' OR url LIKE '%login%';"),
            ("Recherche par indicateurs", "Message-ID, URL, domaine, hash, IP source du clic, user-agent."),
        ),
        ("Bloquer domaine/URL/IP.", "Purger emails similaires.", "Mettre en quarantaine la piece jointe.", "Revoquer sessions et reset mot de passe si credentials saisis."),
        ("Supprimer regles mail suspectes.", "Nettoyer postes exposes.", "Mettre a jour mail gateway.", "Sensibiliser utilisateurs cibles."),
        ("EML original", "En-têtes", "URLs", "Pieces jointes", "Destinataires", "Logs de clic", "Exports mail gateway/proxy"),
        ("Mail gateway", "Microsoft 365/Google Workspace audit", "Proxy", "DNS", "EDR", "IAM", "SIEM"),
        "Un utilisateur signale un email suspect ou une passerelle mail detecte une campagne.",
    ),
    "compromission_compte": profile(
        "compromission_compte",
        "Compromission de compte",
        ("compromission de compte", "compte compromis", "account compromise"),
        "Suspicion d'utilisation non autorisee d'un compte utilisateur ou privilegie.",
        "Confirmer la compromission, stopper l'acces non autorise et reconstruire les actions realisees.",
        "high",
        ("Impossible travel.", "IP ou pays rare.", "MFA fatigue.", "Regles mail de transfert.", "Connexion reussie apres echecs."),
        ("Construire la chronologie des connexions.", "Verifier sessions, MFA, tokens OAuth et regles mail.", "Analyser les actions mail, SaaS, VPN et AD.", "Rechercher les memes IP sur d'autres comptes."),
        (("KQL - connexions", 'SigninLogs\n| summarize count(), ips=make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)'), ("Lucene - auth", 'event.category:authentication AND event.outcome:(failure OR success)'), ("Pseudo-SQL - impossible travel", "SELECT user, source_ip, country, timestamp FROM auth_events ORDER BY timestamp DESC;"), ("Windows Event ID", "4624/4625, 4672, 4720/4732.")),
        ("Revoquer sessions.", "Forcer reset mot de passe.", "Verifier MFA.", "Supprimer regles mail et consentements OAuth suspects."),
        ("Rotation secrets.", "Revue privileges.", "Correction cause racine.", "Surveillance 7 a 14 jours."),
        ("Logs connexion", "IP", "User-agent", "Evenements MFA", "Actions realisees", "Regles mail"),
        ("IAM/SSO", "AD", "VPN", "Mail audit", "EDR", "SIEM"),
        "Un compte presente des connexions inhabituelles, MFA fatigue ou changements non attendus.",
    ),
    "alerte_edr": profile(
        "alerte_edr",
        "Alerte EDR",
        ("alerte edr", "edr", "detection edr", "alerte xdr"),
        "Alerte endpoint portant sur un processus, fichier, comportement ou indicateur potentiellement malveillant.",
        "Qualifier l'alerte et choisir entre faux positif, PUP, malware ou intrusion.",
        "high",
        ("Processus parent/enfant incoherent.", "Hash inconnu.", "Ligne de commande suspecte.", "Connexion reseau rare.", "Execution depuis AppData ou Temp."),
        ("Extraire arbre processus.", "Verifier hash, signature, reputation et prevalence.", "Analyser fichiers, registre et connexions.", "Chercher le meme indicateur sur le parc."),
        (("KQL - process", 'DeviceProcessEvents\n| where SHA256 == "HASH" or FileName =~ "process.exe"'), ("Lucene - hash", 'process.hash.sha256:"HASH" OR process.name:"process.exe"'), ("Pseudo-SQL - prevalence", "SELECT hostname, user, sha256 FROM process_events WHERE sha256='HASH';"), ("Pivot", "hash, process, parent, user, hostname, IP, domaine.")),
        ("Isoler hote si risque eleve.", "Quarantaine fichier.", "Bloquer hash/IP/domaine.", "Suspendre compte si necessaire."),
        ("Supprimer persistence.", "Patch application exploitee.", "Reinstallation si compromission profonde.", "Scan EDR final."),
        ("Alerte EDR", "Timeline", "Hash", "Commande", "Parent process", "Connexions"),
        ("EDR", "SIEM", "Sysmon", "Windows Security", "Firewall", "Proxy", "DNS"),
        "L'EDR signale un comportement suspect, un fichier ou une execution anormale.",
    ),
    "powershell_suspect": profile(
        "powershell_suspect",
        "Execution PowerShell suspecte",
        ("powershell suspect", "execution powershell suspecte", "powershell"),
        "Execution PowerShell potentiellement malveillante, obfusquee ou utilisee pour telechargement distant.",
        "Analyser la commande, identifier la charge utile et contenir l'hote si necessaire.",
        "high",
        ("EncodedCommand ou -enc.", "ExecutionPolicy Bypass.", "IEX ou Invoke-WebRequest.", "Base64 longue.", "Event ID 4104, 4688, Sysmon Event ID 1."),
        ("Collecter commande brute et script block.", "Decoder Base64 sans executer.", "Identifier URL, payload, hash et persistence.", "Verifier proxy, DNS, EDR et processus enfants."),
        (("KQL - PowerShell", 'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-enc", "IEX", "Invoke-WebRequest", "Bypass")'), ("Lucene - Event IDs", 'winlog.event_id:(4104 OR 4688 OR 1) AND process.name:powershell.exe'), ("Pseudo-SQL - command", "SELECT hostname,user,command_line FROM process_events WHERE process_name='powershell.exe';"), ("Windows Event ID", "4104/4103, 4688, Sysmon 1/3.")),
        ("Isoler poste si payload execute.", "Bloquer URL/IP/hash.", "Stopper processus enfants.", "Preserver logs PowerShell."),
        ("Supprimer payload.", "Revoquer credentials exposes.", "Activer Script Block Logging.", "Durcir politiques PowerShell."),
        ("Commande brute", "Commande decodee", "Event ID 4104", "Hash", "URL/IP", "Hostname", "Utilisateur"),
        ("PowerShell logs", "Windows Security", "Sysmon", "EDR", "Proxy", "DNS", "SIEM"),
        "Un evenement signale une commande PowerShell encodee, obfusquee ou telechargeant du code.",
    ),
    "fuite_donnees": profile(
        "fuite_donnees",
        "Fuite de donnees",
        ("fuite de donnees", "exfiltration", "data leak", "data exfiltration"),
        "Suspicion de sortie, partage ou acces non autorise a des donnees sensibles.",
        "Identifier les donnees concernees, stopper l'exfiltration et fournir les elements RSSI/DPO.",
        "critical",
        ("Volume sortant inhabituel.", "Cloud storage personnel.", "Emails externes massifs.", "Compression de fichiers.", "Acces anormal a des partages."),
        ("Construire timeline acces/transferts.", "Identifier fichiers, volumes, destinations et labels.", "Verifier emails externes, partages publics et uploads cloud.", "Qualifier obligations de notification avec RSSI/DPO."),
        (("KQL - volume", 'CommonSecurityLog\n| summarize bytes_out=sum(SentBytes) by SourceUserName, DestinationHostName'), ("Lucene - cloud", 'url.domain:(drive.google.com dropbox.com mega.nz wetransfer.com)'), ("Pseudo-SQL - mail externe", "SELECT sender, SUM(attachment_size) FROM mail_events GROUP BY sender;"), ("Pivot", "user, hostname, destination, archive, extension, label DLP.")),
        ("Suspendre partage public.", "Bloquer destination si actif.", "Suspendre compte si usage malveillant.", "Preserver preuves cloud/DLP."),
        ("Revoquer acces.", "Modifier droits sur partages.", "Supprimer liens publics.", "Corriger configuration DLP/CASB."),
        ("Horodatages", "IP sources/destinations", "Utilisateur", "Hostname", "Fichiers", "Volumes", "Exports DLP/CASB"),
        ("Proxy", "Firewall", "CASB", "Cloud audit", "Mail gateway", "DLP", "Fileserver audit", "SIEM"),
        "Un transfert sortant, partage public ou acces large aux donnees sensibles est detecte.",
    ),
    "brute_force_vpn": profile(
        "brute_force_vpn",
        "Brute force VPN",
        ("brute force vpn", "vpn brute force", "attaque vpn", "bruteforce vpn"),
        "Tentatives repetitives d'authentification VPN visant un ou plusieurs comptes.",
        "Identifier la source, proteger les comptes cibles et verifier l'absence de succes apres echecs.",
        "high",
        ("Nombreux echecs d'authentification.", "Meme utilisateur cible.", "Meme IP source.", "Succes apres echecs.", "Geolocalisation inhabituelle.", "MFA fatigue."),
        ("Grouper echecs par IP, user et pays.", "Chercher succes apres echecs.", "Verifier MFA approvals/denials.", "Analyser activites post-connexion."),
        (("KQL - echecs VPN", 'VPNAuthentication\n| where Result =~ "Failure"\n| summarize failures=count() by SourceIP, User, bin(TimeGenerated, 15m)'), ("Lucene - auth VPN", 'event.dataset:vpn AND event.outcome:(failure OR success)'), ("Pseudo-SQL - brute force", "SELECT user, source_ip, COUNT(*) FROM vpn_auth WHERE outcome='failure' GROUP BY user, source_ip HAVING COUNT(*) > 10;"), ("Windows Event ID", "4625 echecs, 4624 succes, logs NPS/RADIUS/MFA.")),
        ("Bloquer IP source si valide.", "Revoquer sessions VPN suspectes.", "Reset mot de passe des comptes a risque.", "Verifier MFA."),
        ("Ajuster rate limiting.", "Renforcer MFA.", "Revoir verrouillage comptes.", "Surveiller comptes cibles 7 jours."),
        ("Logs VPN", "IP source", "Pays/ASN", "Utilisateurs", "Echecs/succes", "Evenements MFA", "Session ID"),
        ("VPN logs", "IAM/SSO", "AD Security", "MFA logs", "Firewall", "GeoIP", "SIEM"),
        "Le VPN enregistre de nombreux echecs, parfois suivis d'une connexion reussie inhabituelle.",
    ),
}


def list_incidents() -> tuple[IncidentProfile, ...]:
    """Return supported incident profiles sorted by display name."""
    return tuple(sorted(INCIDENTS.values(), key=lambda item: item.display_name))


def get_incident(identifier: str) -> IncidentProfile:
    """Resolve an incident profile from a key, display name, or alias."""
    requested = normalize_key(identifier)
    for incident in INCIDENTS.values():
        candidates = (incident.key, incident.display_name, *incident.aliases)
        if requested in {normalize_key(candidate) for candidate in candidates}:
            return incident
    raise KeyError(identifier)
