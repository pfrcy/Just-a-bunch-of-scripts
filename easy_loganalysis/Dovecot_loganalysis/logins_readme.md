# Dovecot Login Log Analyzer

Ein Python-Script zur Analyse von Dovecot Mail-Server-Logs. Es extrahiert alle erfolgreichen und fehlgeschlagenen Login-Versuche und filtert bestimmte IP-Adressen heraus.

## Erkannte Login-Typen

Das Script erkennt folgende Dovecot-Log-Einträge:

| Typ | Beschreibung | Beispiel |
|-----|--------------|----------|
| **ERFOLGREICH** | Erfolgreiche POP3/IMAP-Logins | `dovecot: pop3-login: Login: user=<...>` |
| **FEHLGESCHLAGEN** | Password Mismatch | `dovecot: auth-worker: Password mismatch` |
| **FEHLGESCHLAGEN** | Connection closed (auth failed) | `dovecot: imap-login: Disconnected: Connection closed (auth failed)` |

## Ausgabe-Felder

- **Datum/Zeit**: Timestamp des Login-Versuchs
- **Benutzer**: E-Mail-Account/Username
- **IP-Adresse**: Quell-IP des Login-Versuchs
- **Status**: `ERFOLGREICH` oder `FEHLGESCHLAGEN`
- **Service**: `POP3`, `IMAP` oder `AUTH`

## Voraussetzungen

- Python 3.6 oder höher
- Standard-Bibliotheken: `re`, `argparse`, `sys`, `pathlib`
---
## Verwendung
### Einzelne IP ausschließen:


```bash
python dovecot_log_analyzer.py <logname>_2025-xx-xx.log --exclude-ips 1.1.1.1

```
### Mehrere IPs komma-separiert:


```bash
python dovecot_log_analyzer.py oplux_2025-09-29.log --exclude-ips "1.1.1.1,8.8.8.8"

```
### IPs aus Datei :
exclude_ips.txt


```bash
python dovecot_log_analyzer.py oplux_2025-09-29.log --exclude-ips exclude_ips.txt

```
Die exclude_ips.txt sollte so formatiert sein:

```
# Kommentare mit # sind erlaubt
1.1.1.1
8.8.8.8
192.168.1.1
```
