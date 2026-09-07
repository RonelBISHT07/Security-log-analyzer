from collections import Counter, defaultdict
from datetime import datetime
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sys

LOG_FILE = "security.log"
CREDENTIALS_FILE = "users.json"
SUSPICIOUS_THRESHOLD = 3

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\w+)\s+user=(\w+)$"
)

# -----------------------------------------------------------------------------
# AUDIT LOG WRITER & NETWORK HELPERS
# -----------------------------------------------------------------------------


def get_client_ip() -> str:
    """Detects local network IP or falls back to loopback."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_valid_ipv4(ip: str) -> bool:
    """Validates whether a string is a legitimate IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def write_security_log(event_type: str, username: str, ip: str = None):
    """Appends an event formatted to match the parsing pattern."""
    if not ip:
        ip = get_client_ip()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{now} {ip} {event_type} user={username}\n"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except OSError as err:
        print(f"[Warning] Failed to write to {LOG_FILE}: {err}")


# -----------------------------------------------------------------------------
# AUTHENTICATION MODULE
# -----------------------------------------------------------------------------


def load_user_db():
    """Loads users from JSON storage, or initializes an empty map."""
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    try:
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_user_db(db):
    """Saves user credentials to disk safely."""
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hashes a password with a 16-byte hex salt using SHA-256."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hashed, salt


def register_user(db):
    """Handles new user creation with custom IP assignment."""
    print("\n--- Create New Account ---")
    username = input("Enter username: ").strip()

    if not username:
        print("[Error] Username cannot be blank.")
        return False

    if username in db:
        print("[Error] That username already exists. Please login instead.")
        return False

    # IP address input with validation
    default_ip = get_client_ip()
    user_ip = input(f"Enter IP address [press Enter for default {default_ip}]: ").strip()

    if not user_ip:
        user_ip = default_ip
    elif not is_valid_ipv4(user_ip):
        print(f"[Error] '{user_ip}' is not a valid IPv4 address (e.g., 192.168.1.50).")
        return False

    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if not password:
        print("[Error] Password cannot be blank.")
        return False

    if password != confirm_password:
        print("[Error] Passwords do not match.")
        return False

    pw_hash, salt = hash_password(password)
    db[username] = {
        "hash": pw_hash,
        "salt": salt,
        "ip": user_ip,
    }
    save_user_db(db)
    print(
        f"[Success] Account '{username}' registered with IP '{user_ip}'! You can now log in."
    )
    return True


def authenticate(db):
    """Authenticates user and writes their assigned IP to security.log."""
    print("\n--- Terminal Login ---")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    fallback_ip = get_client_ip()

    if not username:
        print("[Error] Username cannot be blank.")
        write_security_log("LOGIN_FAILED", "unknown", fallback_ip)
        return None

    if username not in db:
        print("[Error] Invalid username or password.")
        write_security_log("LOGIN_FAILED", username, fallback_ip)
        return None

    # Retrieve registered IP address
    assigned_ip = db[username].get("ip", fallback_ip)
    stored_hash = db[username]["hash"]
    stored_salt = db[username]["salt"]
    computed_hash, _ = hash_password(password, stored_salt)

    if secrets.compare_digest(stored_hash, computed_hash):
        print(f"\n[Success] Welcome back, {username}!")
        write_security_log("LOGIN_SUCCESS", username, assigned_ip)
        return username

    print("[Error] Invalid username or password.")
    write_security_log("LOGIN_FAILED", username, assigned_ip)
    return None


def auth_gateway():
    """Entry portal requiring registration or login before granting access."""
    db = load_user_db()

    while True:
        print("\n" + "=" * 40)
        print("     SECURITY CONSOLE AUTHENTICATION    ")
        print("=" * 40)
        print("1. Login")
        print("2. Register New User")
        print("3. Exit")
        print("=" * 40)

        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            if not db:
                print("\n[Notice] No users found on this system. Please register first.")
                continue
            active_user = authenticate(db)
            if active_user:
                return active_user
        elif choice == "2":
            register_user(db)
            db = load_user_db()
        elif choice == "3":
            print("Access cancelled. Exiting...")
            sys.exit(0)
        else:
            print("[Error] Invalid option. Enter 1, 2, or 3.")


# -----------------------------------------------------------------------------
# LOG PARSING & AUDITING MODULE
# -----------------------------------------------------------------------------


def render_progress_bar(current, total, bar_length=40, prefix="Parsing Logs"):
    """Renders an animated progress bar on a single terminal line."""
    percent = 1.0 if total == 0 else min(current / total, 1.0)
    filled_length = int(bar_length * percent)
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    sys.stdout.write(f"\r{prefix}: [{bar}] {percent * 100:6.2f}% Complete")
    sys.stdout.flush()


def parse_log_file(filepath):
    """Reads and parses the log file line-by-line while rendering a progress bar."""
    records = []
    malformed_lines = []

    if not os.path.exists(filepath):
        print(f"[Error] File '{filepath}' not found.")
        return records

    total_bytes = os.path.getsize(filepath)
    processed_bytes = 0

    with open(filepath, "r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            processed_bytes += len(line.encode("utf-8"))
            stripped_line = line.strip()

            if stripped_line:
                match = LOG_PATTERN.match(stripped_line)
                if match:
                    timestamp, ip, event_type, username = match.groups()
                    records.append(
                        {
                            "timestamp": timestamp,
                            "ip": ip,
                            "event_type": event_type,
                            "username": username,
                        }
                    )
                else:
                    malformed_lines.append((line_num, stripped_line))

            render_progress_bar(processed_bytes, total_bytes)

    render_progress_bar(total_bytes, total_bytes)
    sys.stdout.write("\n")
    sys.stdout.flush()

    for num, entry in malformed_lines:
        print(f"[Warning] Skipped malformed entry at line {num}: '{entry}'")

    return records


def analyze_logs(records):
    """Calculates event counts, failed logins per IP, and suspicious IPs."""
    event_counts = Counter()
    failed_logins_by_ip = defaultdict(int)

    for record in records:
        event_counts[record["event_type"]] += 1
        if record["event_type"] == "LOGIN_FAILED":
            failed_logins_by_ip[record["ip"]] += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_logins_by_ip.items()
        if count >= SUSPICIOUS_THRESHOLD
    }

    return event_counts, failed_logins_by_ip, suspicious_ips


def display_report(event_counts, failed_logins_by_ip, suspicious_ips):
    """Prints the initial security audit summary."""
    print("\n" + "=" * 40)
    print("       SECURITY LOG ANALYSIS REPORT     ")
    print("=" * 40)

    print("\n--- Event Counts ---")
    if not event_counts:
        print("No valid events found.")
    for event, count in event_counts.items():
        print(f"{event:<16} : {count}")

    print("\n--- Failed Login Attempts by IP ---")
    if not failed_logins_by_ip:
        print("No failed logins detected.")
    for ip, count in sorted(failed_logins_by_ip.items()):
        print(f"{ip:<16} : {count}")

    print("\n--- Suspicious IPs (>= 3 Failed Attempts) ---")
    if not suspicious_ips:
        print("None detected.")
    for ip, count in suspicious_ips.items():
        print(f"[ALERT] {ip:<10} has {count} failed login attempts!")


def search_logs(records):
    """Interactive filtering menu for IP, Event Type, or Username."""
    while True:
        print("\n" + "-" * 35)
        print("Log Search / Filter Menu")
        print("1. Search by IP Address")
        print("2. Search by Event Type")
        print("3. Search by Username")
        print("4. Exit")
        print("-" * 35)

        choice = input("Select an option (1-4): ").strip()

        if choice == "4":
            print("Exiting log analyzer. Goodbye!")
            break

        fields = {"1": "ip", "2": "event_type", "3": "username"}
        if choice not in fields:
            print("Invalid selection. Please choose 1, 2, 3, or 4.")
            continue

        target_field = fields[choice]
        query = input(f"Enter {target_field.replace('_', ' ')} to search: ").strip()

        matches = [
            r for r in records if r[target_field].lower() == query.lower()
        ]

        print(
            f"\nResults found ({len(matches)} match{'es' if len(matches) != 1 else ''}):"
        )
        if not matches:
            print("  No records found matching your query.")
        else:
            for r in matches:
                print(
                    f"  {r['timestamp']} | {r['ip']:<15} | {r['event_type']:<14} | user={r['username']}"
                )


def main():
    # 1. Terminal authentication gate
    auth_gateway()

    # 2. Parse the log file (includes the newly logged login attempt)
    records = parse_log_file(LOG_FILE)
    if not records:
        print("No valid records to analyze.")
        return

    # 3. Analyze, show report, and open search menu
    event_counts, failed_logins, suspicious_ips = analyze_logs(records)
    display_report(event_counts, failed_logins, suspicious_ips)
    search_logs(records)


if __name__ == "__main__":
    main()