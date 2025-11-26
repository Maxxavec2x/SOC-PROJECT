# Fiche descriptif des règles

## Internal Vertical Port Scan - simple

**Détecte** :
- Une IP source (`src_ip`) ciblant >10 ports sur une même IP destination (`dest_ip`).
- Indique une **reconnaissance réseau** (ex : scan Nmap).

**Faux positifs** :
- Scans légitimes (monitoring, outils internes).
- Protocoles utilisant plusieurs ports (ex : VoIP).

**Actions** :
1. Vérifier si `src_ip` est interne/externe.
2. Bloquer temporairement si suspect.
3. Corréler avec d'autres alertes.

**Criticité** : Moyen/Élevé.

## cat /etc/passwd

**Détecte** :
- Commandes contenant `/etc/passwd` dans les logs Kunai.
- Peut indiquer :
  - **Énumération de comptes** (reconnaissance).
  - **Exfiltration d’informations** (vol de mots de passe hashés).

**Faux positifs** :
- Administrateurs légitimes (ex : `cat /etc/passwd` pour du dépannage).
- Scripts automatisés de gestion système.

**Actions** :
1. Vérifier l’utilisateur (`info.task.user`) et le processus (`info.task.name`).
2. Confirmer si l’action est justifiée (ex : ticket IT ouvert).
3. Bloquer l’utilisateur si activité non autorisée.

**Criticité** : **Élevée** (si utilisateur non privilégié).

## Utilisation de LSASS

**Détecte** :
- Événements de sécurité Windows impliquant `lsass.exe` (Local Security Authority Subsystem Service).
- Peut indiquer :
  - **Vol de credentials** (ex : Mimikatz, dump de mémoire LSASS).
  - **Attaque par pass-the-hash/ticket**.

**Faux positifs** :
- Mises à jour Windows ou outils légitimes (ex : sauvegardes, antivirus).
- Administrateurs utilisant des outils comme ProcDump.

**Actions** :
1. Vérifier l’utilisateur et le processus parent.
2. Isoler la machine si activité suspecte.
3. Analyser la mémoire pour traces d’outils malveillants.

**Criticité** : **Élevée**.

## Modification clé registre RUN

**Détecte** :
- Ajout/suppression/modification dans la ruche **`Run`** du registre Windows (`CurrentVersion\Run`).
- Indique une **persistance malveillante** (ex : malware, ransomware).

**Faux positifs** :
- Logiciels légitimes (ex : mises à jour, outils IT).
- Exclusions déjà appliquées : OneDrive, Teams, EdgeUpdate, GoogleUpdate.

**Actions** :
1. Vérifier l’utilisateur (`User`) et le processus à l’origine.
2. Analyser la valeur ajoutée (`NewValue/Details`) :
   - Chemin vers un exécutable inconnu ?
   - Script PowerShell/VBS suspect ?
3. Supprimer la clé si malveillante et investiguer la machine.

**Criticité** : **Élevée**.

## enumération

**Détecte** :
- **Commandes d'énumération Linux** (reconnaissance, post-exploitation).
- Exemples : `whoami`, `cat /etc/passwd`, `netstat`, `curl`, `crontab -l`, etc.
- **Seuil** : 3+ commandes différentes en 1 minute sur un même hôte.

**Faux positifs** :
- Administrateurs ou scripts légitimes (ex : audits, maintenance).
- Outils de monitoring ou de sauvegarde.

**Actions** :
1. **Vérif# Détection d'énumération système Linux

**Détecte** :
- **Commandes d'énumération Linux** (reconnaissance, post-exploitation).
- Exemples : `whoami`, `cat /etc/passwd`, `netstat`, `curl`, `crontab -l`, etc.
- **Seuil** : 3+ commandes différentes en 1 minute sur un même hôte.

**Faux positifs** :
- Administrateurs ou scripts légitimes (ex : audits, maintenance).
- Outils de monitoring ou de sauvegarde.

**Actions** :
1. **Vérifier l’utilisateur** et le contexte (ex : connexion SSH récente ?).
2. **Analyser les commandes** :
   - Séquence suspecte (ex : `whoami` → `cat /etc/shadow` → `netstat`) ?
   - Commandes inhabituelles pour l’utilisateur/hôte ?
3. **Isoler l’hôte** si activité non autorisée.
4. **Rechercher des traces** de compromission (ex : fichiers modifiés, connexions sortantes).

**Criticité** : **Élevée** (si utilisateur non privilégié ou commandes sensibles).

**Exemple d’alerte** :
ier l’utilisateur** et le contexte (ex : connexion SSH récente ?).
2. **Analyser les commandes** :
   - Séquence suspecte (ex : `whoami` → `cat /etc/shadow` → `netstat`) ?
   - Commandes inhabituelles pour l’utilisateur/hôte ?
3. **Isoler l’hôte** si activité non autorisée.
4. **Rechercher des traces** de compromission (ex : fichiers modifiés, connexions sortantes).

**Criticité** : **Élevée** (si utilisateur non privilégié ou commandes sensibles).

## ASREP-Roasting

**Détecte** :
- **Tentative de pré-authentification Kerberos échouée** (`PreAuthType=0`).
- Peut indiquer :
  - **Attaque par brute force** sur des comptes Active Directory.
  - **Utilisation d’outils** comme Rubeus, Mimikatz, ou Impacket.

**Faux positifs** :
- Comptes verrouillés ou mots de passe expirés.
- Erreurs de configuration (ex : horloge non synchronisée).

**Actions** :
1. **Vérifier la source** (`Source IP`) :
   - Interne ou externe au réseau ?
   - IP connue pour des activités malveillantes ?
2. **Analyser le compte** (`User`) :
   - Compte privilégié ou sensible ?
   - Activité inhabituelle (ex : connexions hors heures) ?
3. **Bloquer l’IP** si attaque confirmée.
4. **Réinitialiser le mot de passe** du compte ciblé.

**Criticité** : **Élevée** (risque de compromission de compte).

## Action sur la clé de registre Run

**Détecte** :
- **Modifications dans les clés de registre Windows liées à l'exécution automatique** (ex : `HKLM\...\Run`, `HKCU\...\Run`).
- Indique une **persistance malveillante** (ex : malware, ransomware, backdoor).

**Faux positifs** :
- Installations/logiciels légitimes (ex : mises à jour, outils IT).
- Administrateurs configurant des tâches planifiées.

**Actions** :
1. **Vérifier la clé modifiée** :
   - Chemin exact (ex : `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
   - Valeur ajoutée/supprimée (ex : chemin vers un exécutable suspect).
2. **Analyser l’utilisateur/processus** à l’origine.
3. **Supprimer la clé** si malveillante et investiguer l’hôte.
4. **Corréler avec d’autres alertes** (ex : création de processus inconnu).

**Criticité** : **Élevée**.

## Dump LSASS

**Détecte** :
- **Utilisation d'outils de dump de mémoire** (ex : `procdump.exe`, `mimikatz.exe`).
- **Commandes suspectes** ciblant `lsass.exe` ou utilisant `sekurlsa`/`procdump -ma`.
- Indique une **tentative de vol de credentials** (ex : extraction de mots de passe en clair).

**Faux positifs** :
- Administrateurs légitimes (ex : dépannage, diagnostics).
- Outils de sécurité autorisés (ex : sauvegardes mémoire).

**Actions** :
1. **Vérifier l’utilisateur** (`user`) et le processus parent (`ParentImage`).
2. **Isoler immédiatement la machine** si activité non autorisée.
3. **Analyser le dump** (si présent) et supprimer les traces.
4. **Révoquer les sessions Kerberos** du compte concerné.

**Criticité** : **Critique**.

## Test - Création de tâche planifiée Windows

**Détecte** :
- **Création ou modification d'une tâche planifiée** dans Windows (via `schtasks` ou l'interface graphique).
- Peut indiquer :
  - **Persistance malveillante** (ex : exécution périodique de malware).
  - **Élévation de privilèges** (ex : tâche exécutée en tant qu'administrateur).

**Faux positifs** :
- Administrateurs configurant des tâches légitimes (ex : mises à jour, sauvegardes).
- Logiciels nécessitant des tâches planifiées (ex : antivirus, outils de monitoring).

**Actions** :
1. **Vérifier l'utilisateur** et le contexte de la tâche :
   - Qui a créé/modifié la tâche ?
   - La tâche est-elle signée ou connue ?
2. **Analyser la commande associée** :
   - Chemin vers un exécutable suspect ?
   - Arguments inhabituels (ex : scripts PowerShell, commandes obfuscées) ?
3. **Désactiver/supprimer la tâche** si malveillante.
4. **Investiguer l'hôte** pour d'autres signes de compromission.

**Criticité** : **Élevée** (si utilisateur non privilégié ou tâche suspecte).

## Scan réseau (port ou ip)

**Détecte** :
- **Requêtes HTTP GET répétées** (même `clientip`, `user_agent`, `referer`) avec un code **200** et des données retournées (`bytes > 0`).
- Peut indiquer :
  - **Scraping automatisé** (ex : collecte de données).
  - **Scan de vulnérabilités** (ex : recherche de pages sensibles).
  - **Attaque par force brute** sur des endpoints.

**Faux positifs** :
- Bots légitimes (ex : moteurs de recherche, outils de monitoring).
- Utilisateurs naviguant rapidement sur le site.

**Actions** :
1. **Vérifier l’IP source** (`clientip`) :
   - Est-elle connue pour des activités malveillantes ?
   - Géolocalisation inhabituelle ?
2. **Analyser le `user_agent`** :
   - Agent générique (ex : `curl`, `Python-urllib`) ?
   - Agent connu de bots malveillants ?
3. **Bloquer l’IP** si activité suspecte confirmée (ex : WAF, firewall).
4. **Surveiller les endpoints ciblés** pour des tentatives d’exploitation.

**Criticité** : **Moyenne à Élevée**


## Linux Auditd Sudo Or Su Execution

**Détecte** :
- **Utilisation de `sudo` ou `su`** via les logs `auditd`.
- Peut indiquer :
  - **Élévation de privilèges** (ex : utilisateur non autorisé).
  - **Mouvement latéral** (ex : utilisation de `su` pour changer d'utilisateur).

**Faux positifs** :
- Administrateurs légitimes exécutant des commandes privilégiées.
- Scripts automatisés nécessitant des droits élevés.

**Actions** :
1. **Vérifier l'utilisateur** et la commande exécutée (`proctitle`) :
   - La commande est-elle justifiée ?
   - Utilisateur habituel ou inhabituel ?
2. **Analyser le contexte** :
   - Heure d'exécution (hors heures de travail ?).
   - Autres activités suspectes sur le même hôte.
3. **Bloquer l'utilisateur** si activité non autorisée.
4. **Revoir les droits `sudo`** si nécessaire.

**Criticité** : **Moyenne à Élevée** (selon l'utilisateur et la commande).

## Registry Keys Used For Persistence

**Détecte** :
- **Modifications dans des clés de registre critiques** utilisées pour la persistance :
  - `Run`, `RunOnce`, `Winlogon\Shell`, `AppInit_DLLs`, `LSA Security Packages`, `StartupApproved`, `Shell Folders`, `Image File Execution Options`, etc.
- Indique une **persistance malveillante** (ex : malware, backdoor, ransomware).

**Faux positifs** :
- Administrateurs ou outils légitimes (ex : déploiement de logiciels, mises à jour).
- Logiciels nécessitant des modifications de registre (ex : antivirus, outils de gestion).

**Actions** :
1. **Vérifier la clé modifiée** (`registry_path`, `registry_key_name`) :
   - Est-elle associée à une technique de persistance connue ?
2. **Analyser la valeur ajoutée** (`registry_value_data`) :
   - Chemin vers un exécutable suspect ?
   - Commande obfusquée ou inhabituelle ?
3. **Vérifier l'utilisateur et le processus** (`user`, `process_guid`) :
   - Utilisateur privilégié ou processus légitime ?
4. **Supprimer la clé** si malveillante et investiguer l'hôte.
5. **Corréler avec d'autres alertes** (ex : création de processus inconnu).

**Criticité** : **Élevée à Critique** (selon la clé modifiée).

## Malware Registry Abuses

**Détecte** :
- **Modifications dans des clés de registre critiques** liées à la persistance :
  - `Run`, `AppInit_DLLs`, `Winlogon\Shell`, `Winlogon\Userinit`, `LSA`, `Image File Execution Options`, `Netsh`.
- Indique une **persistance malveillante** (ex : malware, backdoor).

**Faux positifs** :
- Administrateurs ou outils légitimes (ex : déploiement de logiciels).
- Logiciels nécessitant des modifications de registre (ex : antivirus).

**Actions** :
1. **Vérifier la clé modifiée** (`registry_path`, `registry_key_name`).
2. **Analyser l'utilisateur** (`user`) et l'hôte (`dest`).
3. **Supprimer la clé** si malveillante et investiguer l'hôte.
4. **Corréler avec d'autres alertes** (ex : création de processus inconnu).

**Criticité** : **Élevée**
