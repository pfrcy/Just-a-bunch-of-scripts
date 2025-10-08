#!/usr/bin/env python3
import re
import argparse
import sys
import os
from datetime import datetime

def load_exclude_ips(exclude_input):
    """
    Lädt IP-Adressen, die ausgeschlossen werden sollen.
    Input kann entweder ein String (einzelne IP oder komma-separierte IPs) 
    oder ein Pfad zu einer .txt-Datei sein.
    """
    exclude_ips = []
    
    # Prüfen, ob es eine Datei ist
    if os.path.isfile(exclude_input):
        try:
            with open(exclude_input, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Leere Zeilen und Kommentare ignorieren
                    if line and not line.startswith('#'):
                        exclude_ips.append(line)
            print(f"IP-Adressen aus Datei geladen: {exclude_input}")
        except Exception as e:
            print(f"Fehler beim Lesen der IP-Liste: {e}")
            sys.exit(1)
    else:
        # Als String behandeln (einzelne IP oder komma-separiert)
        if ',' in exclude_input:
            exclude_ips = [ip.strip() for ip in exclude_input.split(',')]
        else:
            exclude_ips = [exclude_input.strip()]
    
    return exclude_ips

def analyze_dovecot_logs(log_file_path, exclude_ips):
    """
    Analysiert Dovecot-Logs und extrahiert alle Login-Versuche außer der angegebenen IPs
    """
    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            log_content = file.read()
    except FileNotFoundError:
        print(f"Fehler: Datei {log_file_path} nicht gefunden")
        sys.exit(1)
    except Exception as e:
        print(f"Fehler beim Lesen der Log-Datei: {e}")
        sys.exit(1)
    
    lines = log_content.split('\n')
    login_attempts = []
    
    for line in lines:
        if 'dovecot' not in line:
            continue
            
        # Zeitstempel extrahieren
        timestamp_match = re.match(r'^(\w+ \d+ \d+:\d+:\d+)', line)
        if not timestamp_match:
            continue
        timestamp = timestamp_match.group(1)
        
        # Erfolgreiche Logins
        if 'Login:' in line and ('pop3-login' in line or 'imap-login' in line):
            user_match = re.search(r'user=<([^>]+)>', line)
            ip_match = re.search(r'rip=([0-9.]+)', line)
            
            if user_match and ip_match:
                user = user_match.group(1)
                ip = ip_match.group(1)
                
                if ip not in exclude_ips:
                    service = 'POP3' if 'pop3-login' in line else 'IMAP'
                    login_attempts.append({
                        'timestamp': timestamp,
                        'user': user,
                        'ip': ip,
                        'status': 'ERFOLGREICH',
                        'service': service
                    })
        
        # Fehlgeschlagene Logins (Password mismatch)
        elif 'Password mismatch' in line:
            user_ip_match = re.search(r'sql\(([^,]+),([0-9.]+)', line)
            if user_ip_match:
                user = user_ip_match.group(1)
                ip = user_ip_match.group(2)
                
                if ip not in exclude_ips:
                    login_attempts.append({
                        'timestamp': timestamp,
                        'user': user,
                        'ip': ip,
                        'status': 'FEHLGESCHLAGEN',
                        'service': 'AUTH'
                    })
        
        # Verbindungsabbruch wegen Auth-Fehler
        elif 'Connection closed (auth failed' in line:
            user_match = re.search(r'user=<([^>]+)>', line)
            ip_match = re.search(r'rip=([0-9.]+)', line)
            
            if user_match and ip_match:
                user = user_match.group(1)
                ip = ip_match.group(1)
                
                if ip not in exclude_ips:
                    service = 'IMAP' if 'imap-login' in line else 'POP3'
                    login_attempts.append({
                        'timestamp': timestamp,
                        'user': user,
                        'ip': ip,
                        'status': 'FEHLGESCHLAGEN',
                        'service': service
                    })
    
    return login_attempts

def main():
    parser = argparse.ArgumentParser(
        description='Analysiert Dovecot-Logs und filtert Login-Versuche nach IP-Adressen',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # Einzelne IP ausschließen
  %(prog)s mail.log --exclude-ips 95.88.75.176
  
  # Mehrere IPs ausschließen (komma-separiert)
  %(prog)s mail.log --exclude-ips "95.88.75.176,202.61.252.100"
  
  # IPs aus Datei ausschließen
  %(prog)s mail.log --exclude-ips exclude_ips.txt
        """
    )
    
    parser.add_argument('logfile', 
                        help='Pfad zur Dovecot Log-Datei')
    parser.add_argument('--exclude-ips', '-e',
                        required=True,
                        help='IP-Adressen zum Ausschließen (einzeln, komma-separiert oder Pfad zu .txt-Datei)')
    
    args = parser.parse_args()
    
    # IP-Adressen laden
    exclude_ips = load_exclude_ips(args.exclude_ips)
    
    if not exclude_ips:
        print("Fehler: Keine gültigen IP-Adressen zum Ausschließen gefunden")
        sys.exit(1)
    
    # Logs analysieren
    login_attempts = analyze_dovecot_logs(args.logfile, exclude_ips)
    
    # Ausgabe
    print(f"=== DOVECOT LOGIN-ANALYSE ===")
    print(f"Log-Datei: {args.logfile}")
    print(f"Ausgeschlossene IPs: {', '.join(exclude_ips)}")
    print(f"Gefundene Login-Versuche: {len(login_attempts)}")
    print("=" * 100)
    print(f"{'Nr.':<4} {'Datum/Zeit':<16} {'Benutzer':<20} {'IP-Adresse':<16} {'Status':<15} {'Service'}")
    print("-" * 100)
    
    for i, attempt in enumerate(login_attempts, 1):
        print(f"{i:<4} {attempt['timestamp']:<16} {attempt['user']:<20} {attempt['ip']:<16} {attempt['status']:<15} {attempt['service']}")
    
    # Zusammenfassung
    successful = sum(1 for a in login_attempts if a['status'] == 'ERFOLGREICH')
    failed = sum(1 for a in login_attempts if a['status'] == 'FEHLGESCHLAGEN')
    unique_ips = len(set(a['ip'] for a in login_attempts))
    unique_users = len(set(a['user'] for a in login_attempts))
    
    print("=" * 100)
    print(f"ZUSAMMENFASSUNG:")
    print(f"- Erfolgreiche Logins: {successful}")
    print(f"- Fehlgeschlagene Logins: {failed}")
    print(f"- Eindeutige IP-Adressen: {unique_ips}")
    print(f"- Eindeutige Benutzer: {unique_users}")
    print(f"- Ausgeschlossene IPs: {', '.join(exclude_ips)}")

if __name__ == "__main__":
    main()
