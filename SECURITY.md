# Security compliance — NEXARC RMM

Standard: Project Baseline Requirements & Security Manual, Edition 2.0 (258 controls)
Audited: 2026-10-19   ·   Owner: Codex64   ·   Status: NON-COMPLIANT

## Summary
| Part | Controls | Pass | Fail | N/A | Unknown |
|---|---|---|---|---|---|
| I — Baseline requirements | 68 | 54 | 12 | 2 | 0 |
| II — Security controls | 190 | 91 | 28 | 71 | 0 |
| Total | 258 | 145 | 40 | 73 | 0 |

## Authentication posture
Deux publics. Les opérateurs passent par le socle commun, embarqué avec ses essais : quatre facteurs cumulables sur chaque compte — mot de passe (Argon2id, 64 Mio, 3 passes, parallélisme 4, plancher 19 Mio / 2 / 1, rehachage transparent, empreinte scrypt de la 1.x reprise puis rehachée à la connexion, liste de fuites locale, 12 à 1024 caractères), application TOTP (RFC 6238, secret généré côté serveur et scellé AES-256-GCM, QR code dessiné dans le navigateur, rejeu refusé), clés d’accès WebAuthn (résidentes, vérification de l’utilisateur exigée, jusqu’à vingt, nommées et révocables) et dix codes de secours de 100 bits hachés. Politique par facteur : mot de passe et TOTP facultatifs, clé requise pour les administrateurs, qui tiennent deux facteurs dont une clé (deux facteurs sans clé en mode HTTP dégradé, affiché partout). Un mot de passe seul n’ouvre qu’une session d’inscription. Sessions serveur (jeton de 256 bits, empreinte seule en base), renouvelées à chaque changement de niveau, 12 heures au plus et 60 minutes d’inactivité, listées et révocables une à une ou toutes ; les WebSockets de console revérifient la session à la mise à niveau ; l’origine à part des consoles web ne s’ouvre que sur une passe de 256 bits tirée sous une session de membre, gardée par son empreinte, morte avec cette session et au plus tard après huit heures. Renfort de cinq minutes avec le facteur le plus fort avant tout changement de facteur, de rôle ou de politique, avant une suppression, un export, un secret d’appareil, un épinglage, une coupure d’alimentation, une commande libre, ou avant de déclarer une console ou une carte. Rôles : lecture (voit le parc), membre (tâches, réveil, allumage, acquittement), administrateur (commande libre, secrets et accès distants, alimentation qui coupe, comptes). Les machines présentent un jeton d’agent de 192 bits, propre à chacune, gardé en SHA-256, obtenu contre un code d’inscription de 128 bits à usage unique, gardé haché, valable une heure ; le Hub présente un jeton de service (Bearer, 24 caractères au moins, comparé en temps constant) qui n’ouvre que l’état, les tâches (sans la commande libre) et le réveil. Limiteur persistant par adresse et par compte pour les humains, preuve de travail après trois échecs, paliers de verrouillage ; échecs de code et de jeton de machine plafonnés par adresse. La clé maîtresse et le poivre se tournent sans réinscription.


## Findings (audit before fixes)
Relevés en lecture seule avant toute correction (« * » : relevés pendant les corrections et le sondage exploratoire), classés par gravité ; chacun est corrigé dans cette passe par le commit indiqué, avec son essai quand un essai peut l’exprimer.

| # | Gravité | Contrôles | Constat | Commits |
|---|---|---|---|---|
| C1 | CRITICAL | REQ-WEB-002, REQ-WEB-003, SEC-XSS-001, SEC-XSS-004, SEC-HDR-002, SEC-HDR-005, SEC-BE-001 | Le mandataire des consoles servait le HTML d’une carte de gestion sous l’origine de NEXARC, sans politique de script, avec un script en ligne injecté et les en-têtes de cache de la carte : le code d’une carte s’exécutait avec les droits d’une session de NEXARC. | 6b55554, c143c6e |
| C2 | CRITICAL | SEC-CSRF-004, REQ-WEB-005, SEC-AUTHZ-002 | Un simple membre déclarait les adresses internes que le serveur joint (consoles, cartes, nœuds Mesh) ; le mandataire transmettait à la carte le cookie de session de NEXARC. | 5bf30c5, 2e2051c |
| C3 | CRITICAL | REQ-WEB-006, SEC-AUTHZ-002, SEC-AUTHZ-007, SEC-AUTHZ-008 | Une automatisation « commande libre » se réactivait ou se supprimait par un membre et s’exécutait même avec NEXARC_ALLOW_EXEC coupé ; la charge d’une tâche n’était pas validée selon son type, un réveil pouvait viser n’importe quelle adresse. | 201bd1a, d844a37 |
| C4 | CRITICAL | REQ-AUTH-010, SEC-AUTH-003 | Codes d’inscription, jetons d’agents et jeton du Hub sans plafond d’échecs : seul le débit global de 900 requêtes par minute bornait une recherche exhaustive. | 878383a |
| C5 | HIGH | REQ-CRYPT-005, REQ-CRYPT-006 | Code d’inscription de 72 bits, gardé en clair : une lecture de la base donnait des codes encore échangeables contre un jeton d’agent. | 4b84069 |
| C6 | HIGH | REQ-CFG-004, SEC-SECRETS-007, SEC-SECRETS-008 | Clé de connexion Mesh mal formée et jeton SYNAPSE court ou d’exemple acceptés au démarrage. | cc370ed |
| C7 | HIGH | REQ-CFG-005, SEC-LOG-007 | Aucune révocation des jetons d’agents, ni d’un poste ni du parc, sans supprimer les machines et leur historique. | f5c8825 |
| C8 | HIGH | REQ-WEB-005, SEC-CSRF-003 | Trois GET changeaient l’état : tirer un code, l’échanger, relever ses tâches. | b2d52fb |
| C9 | HIGH | REQ-DATA-004, SEC-LOG-001, SEC-DB-010 | Refus décidés par NEXARC, jetons et codes de machine refusés, automatisations, accès distants, réveils et bureaux Mesh absents du journal chaîné. | 8f73149, 5bf30c5, 201bd1a, c403eac |
| C10 | HIGH | REQ-DATA-002 | Redfish acceptait une carte en HTTP et lui envoyait ses identifiants en clair. | 2665875 |
| C11 | HIGH | REQ-CI-003, SEC-DEP-001, SEC-DEP-004 | Dépendances de l’agent en plages de versions, installées sur les postes sans empreinte. | 473830a |
| C12 | HIGH | REQ-DATA-003 | Aucune sauvegarde : rien ne sortait un instantané chiffré de la base. | ced7d3d |
| C13 | HIGH | SEC-API-004 | * La sortie d’une commande libre était rendue à tout compte qui lit le parc, lecture seule comprise. | 76ef8b4 |
| C14 | HIGH | SEC-AUTHZ-003 | * Le rôle de relais venait de la remontée de l’agent : un poste se déclarait relais et recevait les réveils de son segment. | 23936f5 |
| C15 | HIGH | REQ-AUTH-006, REQ-DATA-005 | * Relevé en préparant la mise à jour : l’opérateur d’une 1.x resté au mot de passe d’amorçage était repris sans mot de passe, seul administrateur, sans aucun moyen de reprendre la main (personne pour lui envoyer un lien). | 1048ff3 |
| C16 | MEDIUM | REQ-WEB-008, SEC-API-002, SEC-API-003 | Mises à niveau WebSocket hors du débit, flux d’activité et automatisations sans plafond, inventaire de 512 Kio lu et validé avant le jeton de l’agent. | 9db7974 |
| C17 | MEDIUM | SEC-XSS-006, SEC-API-007 | Message réseau et réponse brute d’une carte rendus au client ; échange d’un code, remontée, relève, passage d’automatisation et acquittement écrits en plusieurs requêtes sans transaction. | fd4ed01, 82e0c38 |
| C18 | MEDIUM | SEC-DB-004 | Installé seul, la clé maîtresse se créait dans le volume de données, à côté de ce qu’elle scelle. | b92e3a0 |
| C19 | MEDIUM | REQ-CI-002 | Analyse statique sans l’agent Python ; aucune mise à jour proposée pour les actions, l’image et les dépendances de l’agent. | 8b742f6 |
| C20 | MEDIUM | REQ-WEB-006 | * Paramètres de requête lus sans schéma et références du chemin sans contrôle de forme. | e480fc9 |
| C21 | MEDIUM | SEC-CSRF-004 | * Les appels à SYNAPSE suivaient une redirection, jeton compris. | 148b701 |
| C22 | MEDIUM | SEC-SECRETS-004 | * Sous Windows, le dossier du jeton de l’agent héritait des droits de lecture des utilisateurs du poste. | 50f6326 |
| C23 | MEDIUM | REQ-WEB-008 | * Le WebSocket écrit à la main renvoyait en écho une trame de contrôle fragmentée ou de plus de 125 octets. | aca6b33 |
| C24 | LOW | SEC-API-007 | * Régression de cette passe (introduite par 8f73149), relevée par le sondage : une commande libre venue du Hub, ou avec le réglage coupé, finissait en erreur interne (500) au lieu d’un refus 403. | cfebf32 |
| C25 | LOW | REQ-DATA-005, SEC-PRIV-003 | * Runbook jamais déroulé ; notice de confidentialité muette sur les sauvegardes et l’origine des consoles. | 694d771, e63412a |

Audit de suivi du 2026-10-19 sur 2.0.3 (mêmes classes de défauts que celles relevées ce jour-là dans les autres services du socle : chemins suivis sur la foi d’une réponse, paramètres lus sous condition, actions de CI en retard), corrigé en 2.0.4 :

| # | Gravité | Contrôles | Constat | Commits |
|---|---|---|---|---|
| D1 | LOW | SEC-CSRF-004, REQ-WEB-005 | Les chemins Redfish suivants (membre d’une collection, cible d’une action) venaient de la carte et étaient collés à son adresse : un `@autre-hôte` ou un `//autre-hôte` envoyait la requête, identifiants compris, ailleurs. L’épinglage du certificat empêchait déjà la poignée de main avec un autre hôte ; ils sont désormais refusés avant toute connexion. | 73038ed |
| D2 | LOW | REQ-WEB-006 | Une route qui rendrait sans lire ses paramètres de requête les laisserait passer : ils sont validés avant toute réponse, quelle que soit la route. | e225a9a |
| D3 | LOW | SEC-DEP-004 | Actions de CI en retard d’une version ; trois montées proposées par Dependabot restées en demandes de fusion. | 2cf0924 |

Suivi du 2026-10-21 (2.0.5) : un poste inscrit avec un nom contenant une espace (« MacBook Pro ») n'apparaissait jamais. L'agent envoyait ce nom comme nom d'hôte et la remontée le refusait (400), alors que l'inscription l'avait accepté. La remontée admet désormais les caractères du nom d'inscription (`src/api.js:23`), toujours sans apostrophe, guillemet, dollar, point-virgule ni barre oblique inverse ; l'agent envoie son vrai nom d'hôte (`agent/nexarc-agent.py:344`) et affiche la raison d'un refus. Essai : `test/nexarc.test.js:219` (nom avec espace accepté ; `;`, `$`, apostrophe, espace en tête, 81 caractères refusés). Aucun contrôle ne change de statut. Essais : 48 du service, 23 de l'agent.
