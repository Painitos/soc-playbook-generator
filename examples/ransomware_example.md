# Playbook SOC - Ransomware

**Entreprise :** ACME  
**Criticité :** critical  
**Version :** 0.1.0

## 1. Résumé exécutif

- **Description courte :** Suspicion de chiffrement malveillant, d'extorsion ou de preparation d'une attaque ransomware.
- **Objectif du playbook :** Qualifier l'etendue, contenir la propagation, preserver les preuves et guider la restauration.
- **Niveau de criticité typique :** critical
- **Équipes concernées :**
- SOC N1/N2
- CSIRT
- Equipe systemes
- Equipe reseau
- Sauvegardes
- RSSI

## 2. Contexte

**Description du scénario :** Un poste ou serveur presente des signes de chiffrement massif, de creation de notes de rancon, ou d'activite laterale SMB inhabituelle.

**Actifs potentiellement concernés :**
- Postes utilisateurs
- Serveurs de fichiers
- Controleurs de domaine
- Shares SMB
- Plateformes de sauvegarde

**Sources de logs utiles :**
- EDR/XDR
- SIEM
- Windows Security logs
- Sysmon
- Fileserver audit
- Firewall
- DNS
- Sauvegardes

**Hypothèses initiales :**
- Le chiffrement peut etre encore actif.
- La compromission initiale peut preceder l'alerte de plusieurs jours.
- La propagation laterale doit etre consideree possible tant que le contraire n'est pas prouve.

## 3. Critères de qualification

**Éléments permettant de distinguer un faux positif d'un incident réel :**
- Operation de chiffrement legitime planifiee et documentee.
- Outil d'administration connu execute par un compte de confiance.
- Activite limitee a un repertoire de test sans extension suspecte.

**Indicateurs techniques à vérifier :**
- Volume eleve de renommages ou modifications de fichiers.
- Extensions inhabituelles ajoutees aux fichiers.
- Creation de fichiers README, RECOVER, DECRYPT ou HOW_TO_RESTORE.
- Execution de vssadmin, wbadmin, bcdedit ou scripts de suppression de sauvegardes.
- Connexions SMB nombreuses vers plusieurs hotes.

**Signaux faibles :**
- Augmentation progressive des erreurs d'acces fichiers.
- Processus bureautique lancant un binaire inconnu.
- Authentifications admin hors horaires.
- DNS vers domaines recents ou peu reputes.

**Critères d'escalade :**
- Chiffrement confirme sur un actif de production.
- Compte privilegie implique.
- Propagation multi-hotes.
- Suppression ou alteration de sauvegardes.
- Presence d'une note de rancon.

## 4. Triage initial

**Questions à se poser :**
- Quel hote a declenche la premiere alerte ?
- Le processus de chiffrement est-il encore actif ?
- Combien d'actifs partagent les memes indicateurs ?
- Des sauvegardes sont-elles touchees ?
- Un compte privilegie est-il utilise ?

**Vérifications rapides :**
- Verifier la timeline EDR des 30 dernieres minutes.
- Rechercher les extensions suspectes sur les partages critiques.
- Controler les connexions SMB sortantes depuis l'hote.
- Identifier le processus parent et la ligne de commande.

**Priorisation :**
- Prioriser les serveurs de fichiers, controleurs de domaine, sauvegardes et actifs metier critiques.
- Escalader immediatement si la propagation ou la suppression de sauvegardes est confirmee.

**Décision possible :**
- Fermer uniquement si une operation legitime est documentee.
- Surveiller si les signaux sont isoles et expliques.
- Traiter en incident si chiffrement, note de rancon ou lateralisation est confirme.

## 5. Investigation technique

**Étapes détaillées d'analyse :**
1. Construire une timeline depuis le premier evenement suspect.
2. Identifier le patient zero, le processus parent et les comptes utilises.
3. Rechercher les memes hash, extensions et noms de fichiers sur le parc.
4. Verifier SMB, RDP, WMI, PsExec et WinRM.
5. Controler les actions sur sauvegardes et shadow copies.
6. Rechercher une exfiltration prealable dans proxy, firewall et DNS.

**Logs à consulter :**
- EDR/XDR
- SIEM
- Windows Security logs
- Sysmon
- Fileserver audit
- Firewall
- DNS
- Sauvegardes

**Artefacts à récupérer :**
- Fichiers chiffres representatifs
- Note de rancon
- Hash des binaires suspects
- Dump de ligne de commande
- Liste des connexions reseau
- Exports EDR de la timeline

**Requêtes SIEM génériques :**
### KQL - chiffrement et notes de rancon

```text
DeviceFileEvents
| where FileName has_any ("README", "RECOVER", "DECRYPT", "HOW_TO_RESTORE") or PreviousFileName != ""
| summarize count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
```

### Lucene - extensions et outils suspects

```text
event.category:file AND (file.name:*README* OR file.extension:(locked encrypted crypt)) OR process.name:(vssadmin.exe wbadmin.exe bcdedit.exe)
```

### Pseudo-SQL - volume de modifications

```text
SELECT hostname, user, process_name, COUNT(*) AS file_events
FROM file_events
WHERE action IN ('rename','modify','delete')
GROUP BY hostname, user, process_name
HAVING COUNT(*) > 500;
```

### Windows Event ID

```text
Rechercher 4688 pour vssadmin/wbadmin/bcdedit, Sysmon 1 pour processus, Sysmon 3 pour connexions, 5140/5145 pour SMB.
```

**Points de vérification SOC :**
- EDR: timeline processus et hash.
- Firewall/proxy: connexions sortantes et telechargements.
- AD: comptes privilegies et GPO modifiees.
- VPN: acces distants recents.
- DNS: domaines recents ou DGA-like.

## 6. Containment

**Actions immédiates de limitation :**
- Isoler immediatement les machines suspectes via EDR ou reseau.
- Desactiver temporairement les comptes compromis ou suspects.
- Bloquer hash, domaines, IP et chemins de fichiers identifies.
- Couper les partages SMB non essentiels si propagation active.
- Proteger les sauvegardes contre modification ou suppression.

**Précautions avant action :**
- Preserver les preuves avant reinstallation.
- Coordonner toute coupure avec les responsables metier.
- Eviter d'eteindre une machine si la memoire vive doit etre preservee.

## 7. Remédiation

**Actions de remédiation :**
- Supprimer le binaire et les taches persistantes.
- Corriger le vecteur initial: patch, configuration, identifiants ou exposition distante.
- Reinitialiser les mots de passe des comptes impliques.
- Reconstruire les machines fortement compromises.
- Restaurer depuis des sauvegardes verifiees et anterieures a la compromission.

**Vérification post-remédiation :**
- Verifier l'absence de nouveaux fichiers chiffres.
- Confirmer que les sauvegardes restaurent correctement.
- Relancer une recherche parc sur les indicateurs.

## 8. Preuves à collecter

- Horodatage du premier fichier chiffre
- Hostname et adresse IP du patient zero
- Utilisateur et comptes privilegies utilises
- Hash des binaires
- Processus et lignes de commande
- Connexions SMB et destinations
- Exports SIEM/EDR horodates

## 9. Communication

**Qui prévenir :**
- SOC lead
- CSIRT
- RSSI
- Equipe infrastructure
- Responsables applicatifs
- Direction de crise si impact majeur

**Message synthétique pour équipe technique :**
> Suspicion ransomware qualifiee: conserver les preuves, isoler les actifs listes et verifier la presence des indicateurs fournis.

**Message synthétique pour management :**
> Un incident de type ransomware est en cours d'analyse. Les actions visent a limiter la propagation, evaluer l'impact metier et preparer une restauration controlee.

**Points à éviter dans la communication :**
- Ne pas annoncer une perte definitive avant validation.
- Ne pas partager d'indicateurs sensibles hors canal approuve.
- Ne pas contacter l'attaquant sans decision formelle.

**Niveau de confidentialité :** Confidentiel securite - diffusion limitee SOC, CSIRT, RSSI et responsables autorises.

## 10. Clôture et retour d'expérience

**Conditions de clôture :**
- Aucun chiffrement actif detecte.
- Vecteur initial identifie ou risque residuel documente.
- Actifs restaures ou reconstruits.
- Indicateurs bloques et surveilles.

**Vérifications finales :**
- Recherche SIEM sur 7 a 30 jours.
- Controle EDR sur tous les hotes touches.
- Validation metier des services restaures.
- Verification de l'integrite des sauvegardes.

**Leçons apprises :**
- Evaluer le delai entre compromission initiale et detection.
- Identifier les controles qui ont manque.
- Mesurer l'efficacite de l'isolation EDR.

**Amélioration des règles de détection :**
- Regle sur suppression de shadow copies.
- Regle sur volume anormal de renommages fichiers.
- Correlation SMB lateral + creation de note de rancon.

**Amélioration du durcissement :**
- Restreindre les droits d'ecriture sur partages.
- Durcir l'administration distante.
- Segmenter les sauvegardes.
- Tester regulierement la restauration.
