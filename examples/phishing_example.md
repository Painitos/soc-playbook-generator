# Playbook SOC - Phishing

**Entreprise :** ACME  
**Criticité :** high  
**Version :** 0.1.0

## 1. Résumé exécutif

- **Description courte :** Email suspect visant a voler des identifiants, executer une piece jointe ou rediriger vers une page malveillante.
- **Objectif du playbook :** Qualifier la campagne, identifier les utilisateurs exposes et bloquer les elements malveillants.
- **Niveau de criticité typique :** medium
- **Équipes concernées :**
- SOC N1/N2
- Equipe messagerie
- Equipe IAM
- RSSI
- Support utilisateurs

## 2. Contexte

**Description du scénario :** Un utilisateur signale un email suspect ou la passerelle mail declenche une alerte sur URL, piece jointe ou usurpation.

**Actifs potentiellement concernés :**
- Boites mail
- Comptes utilisateurs
- Navigateurs
- Postes de travail
- Passerelle mail

**Sources de logs utiles :**
- Mail gateway
- Microsoft 365/Google Workspace audit
- Proxy
- DNS
- EDR
- IAM
- SIEM

**Hypothèses initiales :**
- Des emails similaires peuvent deja etre dans plusieurs boites.
- Un clic utilisateur peut avoir eu lieu avant le signalement.
- L'expediteur visible peut etre usurpe.

## 3. Critères de qualification

**Éléments permettant de distinguer un faux positif d'un incident réel :**
- Campagne interne de sensibilisation connue.
- Domaine partenaire valide confirme par un canal secondaire.
- Lien de tracking marketing legitime et attendu.

**Indicateurs techniques à vérifier :**
- En-tetes SPF, DKIM ou DMARC en echec.
- URL raccourcie ou domaine ressemblant a une marque.
- Piece jointe macro, archive ou HTML.
- Expediteur affiche different du Return-Path.
- Connexion utilisateur vers URL apres reception.

**Signaux faibles :**
- Objet urgent ou pression temporelle.
- Demande d'identifiants ou de paiement.
- Langue inhabituelle pour l'expediteur.
- Domaine cree recemment.

**Critères d'escalade :**
- Utilisateur a saisi des identifiants.
- Piece jointe executee.
- Nombre important de destinataires internes.
- Compte VIP ou privilegie cible.
- Regle de boite mail creee apres reception.

## 4. Triage initial

**Questions à se poser :**
- Qui a recu l'email ?
- Des utilisateurs ont-ils clique ou repondu ?
- La piece jointe a-t-elle ete ouverte ?
- Les controles SPF/DKIM/DMARC sont-ils valides ?
- Existe-t-il des messages similaires ?

**Vérifications rapides :**
- Analyser les en-têtes complets.
- Extraire les URLs et pieces jointes.
- Verifier reputation domaine/IP/hash.
- Rechercher le Message-ID dans la messagerie.
- Croiser avec logs proxy et EDR.

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
1. Parser les en-têtes mail et identifier la chaine de relais.
2. Comparer From, Reply-To, Return-Path et domaine d'authentification.
3. Rechercher emails similaires par sujet, expediteur, URL et hash.
4. Identifier les destinataires, clics et soumissions de formulaire.
5. Verifier les connexions IAM apres le clic.
6. Analyser la piece jointe en environnement controle.
7. Verifier l'apparition de regles de transfert mail.

**Logs à consulter :**
- Mail gateway
- Microsoft 365/Google Workspace audit
- Proxy
- DNS
- EDR
- IAM
- SIEM

**Artefacts à récupérer :**
- Email original au format EML
- En-têtes complets
- URLs extraites
- Pieces jointes et hash
- Liste des destinataires
- Logs de clic proxy
- Captures de la page de phishing si disponibles

**Requêtes SIEM génériques :**
### KQL - recherche emails similaires

```text
EmailEvents
| where SenderFromAddress =~ "sender@example.com" or Subject has "urgent"
| join kind=leftouter EmailUrlInfo on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url
```

### Lucene - clics proxy

```text
url.domain:(example-login.com OR bit.ly) OR url.full:*credential*
```

### Pseudo-SQL - destinataires et clics

```text
SELECT recipient, subject, url, clicked_at
FROM mail_events LEFT JOIN proxy_events USING (message_id)
WHERE sender_domain = 'suspicious.example' OR url LIKE '%login%';
```

### Recherche par indicateurs

```text
Chercher Message-ID, sender IP, URL, domaine, hash de piece jointe, destinataire, user-agent et adresse IP source du clic.
```

**Points de vérification SOC :**
- EDR: verifier execution de piece jointe.
- Firewall/proxy: confirmer acces aux URLs.
- Mail gateway: rechercher et purger messages similaires.
- AD/IAM: verifier connexions anormales apres clic.
- DNS: rechercher resolution du domaine.
- VPN: verifier connexions post-compromission.

## 6. Containment

**Actions immédiates de limitation :**
- Bloquer domaine, URL et IP dans proxy/DNS securise.
- Purger les emails similaires des boites.
- Bloquer ou mettre en quarantaine la piece jointe par hash.
- Forcer reset mot de passe si identifiants saisis.
- Revoquer sessions pour les utilisateurs exposes.

**Précautions avant action :**
- Conserver un exemplaire EML avant purge.
- Eviter de cliquer directement sur les URLs hors environnement d'analyse.
- Coordonner les resets avec le support pour limiter les blocages utilisateurs.

## 7. Remédiation

**Actions de remédiation :**
- Reinitialiser les comptes compromis.
- Supprimer regles mail malveillantes.
- Nettoyer postes ayant execute la piece jointe.
- Mettre a jour les controles mail gateway.
- Informer les utilisateurs cibles avec un message court et actionnable.

**Vérification post-remédiation :**
- Verifier absence de nouvelles connexions suspectes.
- Confirmer purge complete dans la messagerie.
- Relancer recherche sur URL/hash/sujet.
- Valider que les utilisateurs cibles ont applique les consignes.

## 8. Preuves à collecter

- EML original
- Horodatages reception/clic
- Destinataires
- IP d'envoi
- Resultats SPF/DKIM/DMARC
- URLs et domaines
- Hash de pieces jointes
- Exports mail gateway/proxy

## 9. Communication

**Qui prévenir :**
- Equipe messagerie
- SOC lead
- Support utilisateurs
- RSSI si impact large
- IAM si compte compromis

**Message synthétique pour équipe technique :**
> Campagne phishing en cours d'analyse. Merci de bloquer les indicateurs fournis, rechercher les messages similaires et verifier les utilisateurs ayant clique.

**Message synthétique pour management :**
> Une campagne de phishing a ete detectee. Les actions prioritaires sont le retrait des messages, le blocage des liens et la protection des comptes potentiellement exposes.

**Points à éviter dans la communication :**
- Ne pas transferer l'email suspect sans le signaler comme piece jointe.
- Ne pas inclure de liens actifs dans les communications larges.
- Ne pas attribuer l'origine avant confirmation.

**Niveau de confidentialité :** Interne securite - partage possible avec support et messagerie selon besoin.

## 10. Clôture et retour d'expérience

**Conditions de clôture :**
- Emails similaires purges ou controles.
- Indicateurs bloques.
- Utilisateurs exposes identifies.
- Comptes a risque securises.
- Absence d'activite post-clic suspecte.

**Vérifications finales :**
- Recherche mail sur 30 jours.
- Verification proxy des clics tardifs.
- Controle IAM des utilisateurs exposes.
- Validation des nouvelles regles mail gateway.

**Leçons apprises :**
- Identifier pourquoi le message a passe les filtres.
- Mesurer le taux de clic.
- Evaluer la rapidite du signalement utilisateur.

**Amélioration des règles de détection :**
- Regle sur domaines lookalike.
- Correlation email recu + clic proxy.
- Detection de pieces jointes HTML ou archives suspectes.

**Amélioration du durcissement :**
- Renforcer DMARC/SPF/DKIM.
- Activer reecriture et sandboxing des URLs.
- Ameliorer le bouton de signalement phishing.
