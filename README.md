## 🚀 Objectif Général
L'applet permet de gérer les aspects critiques d'une carte à puce :
- **Authentification sécurisée** : PIN, IC Code et sessions chiffrées.
- **Gestion de fichiers** : Support des fichiers systèmes et utilisateurs.
- **Compte financier** : Opérations de crédit, débit et gestion d'historique.
- **Protection des données** : Utilisation de MAC, Checksum et protection contre les overflows/underflows.
- **Cycle de vie** : Réinitialisation sécurisée de la carte.

---

## 🔒 Sécurité et Authentification

### Flags d'état de sécurité
L'état de la carte est contrôlé par plusieurs drapeaux internes :
- `sessionActive` : Session de communication ouverte.
- `isMutualAuthCompleted` : Authentification mutuelle 3DES réussie.
- `isIcVerified` : Code industriel (IC) validé.
- `isCardLocked` : Carte verrouillée (sécurité après échecs répétés).

### Mécanismes de vérification
1. **PIN** : Vérification via `OwnerPIN` (limite de 3 essais).
2. **IC Code** : Code de sécurité constructeur/émetteur.
3. **Session sécurisée** : Challenge aléatoire combiné au Triple DES (3DES).
4. **MAC (Message Authentication Code)** : Garantit l'intégrité de chaque transaction financière.
5. **Checksum** : Vérifie l'intégrité physique du fichier `ACCOUNT` (FF05).

---

## 📁 Système de Fichiers

### Fichiers Système (ACOS3)
| ID | Nom | Description |
| :--- | :--- | :--- |
| **FF02** | MCU | Configuration globale (nombre de fichiers, etc.) |
| **FF03** | FMS | Stockage du code IC (accès Admin) |
| **FF04** | ATTR | Attributs, offsets et permissions des fichiers |
| **FF05** | ACCOUNT | Données financières (Solde, Max, Historique, Checksum) |

### Fichiers Utilisateurs
- **Nombre max** : 31 fichiers.
- **Stockage total** : 2048 octets.
- Chaque fichier définit sa longueur d'enregistrement, ses permissions et son offset global.

---

## 📑 Instructions APDU supportées

| Code (INS) | Nom | Description |
| :--- | :--- | :--- |
| `0x84` | START SESSION | Génère un challenge aléatoire pour l'auth |
| `0x82` | AUTHENTICATE | Réponse au challenge pour l'auth mutuelle |
| `0x20` | SUBMIT CODE | Soumission PIN (P1=06) ou IC (P1=07) |
| `0x24` | CHANGE PIN | Modification du code secret utilisateur |
| `0xA4` | SELECT FILE | Sélection d'un fichier système ou utilisateur |
| `0xB2` | READ RECORD | Lecture d'un enregistrement |
| `0xD2` | WRITE RECORD | Écriture d'un enregistrement |
| `0xE2` | CREDIT | Crédite le compte (nécessite un MAC) |
| `0xE6` | DEBIT | Débite le compte (nécessite un MAC) |
| `0xE8` | REVOKE DEBIT | Annule la dernière transaction de débit |
| `0xE4` | INQUIRE ACC. | Lecture complète du fichier compte |
| `0x30` | CLEAR CARD | Reset complet (PIN, fichiers, solde) |

---

## 🛠 Formats APDU pour les Tests

Pour éviter les erreurs communes comme la `SW 6700` (Wrong Length) ou la `SW 6B20` (Overflow), respectez les formats suivants :

### Commande de Transaction (Crédit/Débit)
Le champ **Data** doit mesurer exactement **11 octets** :

| Offset | Taille | Description |
| :--- | :--- | :--- |
| 0 | 4 octets | **MAC** (Calculé sur les 7 octets suivants) |
| 4 | 1 octet | **Type** (0x01 pour Débit, 0x03 pour Crédit) |
| 5 | 3 octets | **Montant** (Paddé à gauche : `0x00 0xHH 0xLL`) |
| 8 | 4 octets | **TTREF** (Référence de transaction) |

> ⚠️ **Note sur l'erreur 6B20** : Si le montant est envoyé sur 2 octets au lieu de 3, l'alignement est rompu et l'applet interprète mal les données.