"""Project 11: RSA signatures for simulated banking transactions."""
import base64
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

ROOT = Path(__file__).resolve().parent


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def encode(data):
    # A fixed order and spacing give signing and verification identical bytes.
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(data, private_key):
    digest = SHA256.new(encode(data))
    return pss.new(private_key).sign(digest)


def verify(data, signature, public_key):
    try:
        pss.new(public_key).verify(SHA256.new(encode(data)), signature)
        return True
    except (ValueError, TypeError):
        return False


def money_to_paise(text):
    try:
        amount = Decimal(text)
        if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000000"):
            raise ValueError("Amount must be positive and at most 1,000,000,000 INR.")
        paise = amount * 100
        if paise != paise.to_integral_value():
            raise ValueError("Use no more than two decimal places.")
        return int(paise)
    except InvalidOperation:
        raise ValueError("Enter a valid amount, such as 500.00.") from None


def show_money(paise):
    return f"{paise // 100}.{paise % 100:02d}"


class BankingProject:
    def __init__(self, folder=ROOT):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.database = self.folder / "bank.db"
        with sqlite3.connect(self.database) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, signature BLOB NOT NULL
            )""")

    def generate_keys(self):
        keys = self.folder / "keys"
        keys.mkdir(exist_ok=True)
        private_path = keys / "private.pem"
        public_path = keys / "public.pem"
        if private_path.exists() or public_path.exists():
            raise ValueError("Keys already exist. They are kept to verify older records.")
        key = RSA.generate(2048)
        # Only this computer's user should be able to read the private key.
        with private_path.open("xb") as file:
            private_path.chmod(0o600)
            file.write(key.export_key())
        public_path.write_bytes(key.public_key().export_key())

    def key(self, private=False):
        name = "private.pem" if private else "public.pem"
        path = self.folder / "keys" / name
        if not path.exists():
            raise ValueError("Generate the RSA keys first (option 1).")
        return RSA.import_key(path.read_bytes())

    def create_transaction(self, sender, receiver, amount):
        sender, receiver = sender.strip(), receiver.strip()
        if not sender or not receiver or len(sender) > 80 or len(receiver) > 80:
            raise ValueError("Account names must contain 1 to 80 characters.")
        if any(ord(c) < 32 for c in sender + receiver):
            raise ValueError("Account names cannot contain control characters.")
        if sender.casefold() == receiver.casefold():
            raise ValueError("Sender and receiver must be different.")
        data = {"id": str(uuid.uuid4()), "sender": sender, "receiver": receiver,
                "amount_paise": money_to_paise(amount), "currency": "INR", "time_utc": now()}
        signature = sign(data, self.key(private=True))
        if not verify(data, signature, self.key()):
            raise ValueError("The private and public keys do not match.")
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT INTO transactions VALUES (?, ?, ?)",
                       (data["id"], encode(data).decode(), signature))
        return data["id"]

    def rows(self):
        with sqlite3.connect(self.database) as db:
            return db.execute("SELECT id, payload, signature FROM transactions ORDER BY rowid").fetchall()

    def row_valid(self, row):
        record_id, payload, signature = row
        public_key = self.key()
        try:
            data = json.loads(payload)
            return isinstance(data, dict) and data.get("id") == record_id and verify(data, signature, public_key)
        except (ValueError, TypeError):
            return False

    def verify_transaction(self, record_id):
        with sqlite3.connect(self.database) as db:
            row = db.execute("SELECT id, payload, signature FROM transactions WHERE id = ?",
                             (record_id,)).fetchone()
        if row is None:
            raise ValueError("Transaction ID was not found.")
        return self.row_valid(row)

    def tamper_demo(self, record_id):
        with sqlite3.connect(self.database) as db:
            row = db.execute("SELECT id, payload, signature FROM transactions WHERE id = ?",
                             (record_id,)).fetchone()
        if row is None:
            raise ValueError("Transaction ID was not found.")
        changed = json.loads(row[1])
        changed["amount_paise"] += 10000  # Add Rs. 100 to a copy, keeping the old signature.
        return self.row_valid(row), verify(changed, row[2], self.key())

    def export_report(self):
        lines = ["SECURE BANKING TRANSACTION REPORT", "Project 11 | Educational simulation",
                 f"Generated (UTC): {now()}", "Status describes each transaction signature.", ""]
        valid_count = 0
        rows = self.rows()
        for row in rows:
            valid = self.row_valid(row)
            valid_count += int(valid)
            lines.extend([f"ID: {row[0]}", f"Status: {'VALID' if valid else 'INVALID'}",
                          f"Stored transaction: {row[1]}", ""])
        lines.extend([f"Total: {len(rows)}", f"Valid: {valid_count}",
                      f"Invalid: {len(rows) - valid_count}",
                      "A signed report can contain invalid transactions; inspect their status."])
        content = "\n".join(lines) + "\n"
        signature = pss.new(self.key(private=True)).sign(SHA256.new(content.encode()))
        if not self.verify_report_bytes(content.encode(), signature):
            raise ValueError("The private and public keys do not match.")
        reports = self.folder / "reports"
        reports.mkdir(exist_ok=True)
        path = reports / f"report_{uuid.uuid4().hex[:12]}.txt"
        path.write_bytes(content.encode())
        path.with_suffix(".sig").write_bytes(base64.b64encode(signature))
        return path

    def verify_report_bytes(self, content, signature):
        try:
            pss.new(self.key()).verify(SHA256.new(content), signature)
            return True
        except (ValueError, TypeError):
            return False

    def verify_report(self, path):
        path = Path(path)
        content = path.read_bytes()
        try:
            signature = base64.b64decode(path.with_suffix(".sig").read_bytes(), validate=True)
        except ValueError:
            return False
        return self.verify_report_bytes(content, signature)


def main():
    app = BankingProject()
    print("\nSECURE BANKING TRANSACTIONS — Project 11")
    print("RSA digital signature demonstration | No real money is transferred")
    while True:
        print("\n1. Generate RSA keys\n2. Create and sign transaction\n3. List transactions")
        print("4. Verify transaction\n5. Demonstrate tampering on a copy")
        print("6. Export signed report\n7. Verify report\n0. Exit")
        choice = input("Choose: ").strip()
        try:
            if choice == "1":
                app.generate_keys()
                print("2048-bit RSA key pair generated. Keep keys/private.pem secret.")
            elif choice == "2":
                record_id = app.create_transaction(input("Sender account: "),
                    input("Receiver account: "), input("Amount (INR): "))
                print("Transaction signed and saved. ID:", record_id)
            elif choice == "3":
                rows = app.rows()
                if not rows:
                    print("No transactions yet.")
                for row in rows:
                    print(row[0], "VALID" if app.row_valid(row) else "INVALID", row[1])
            elif choice == "4":
                valid = app.verify_transaction(input("Transaction ID: ").strip())
                print("VALID: signature matches." if valid else "INVALID: signature or data does not match.")
            elif choice == "5":
                original, modified = app.tamper_demo(input("Transaction ID: ").strip())
                print("Original:", "VALID" if original else "INVALID")
                print("Copy with INR 100 added:", "VALID" if modified else "INVALID")
                print("The stored transaction was not changed.")
            elif choice == "6":
                print("Report saved:", app.export_report())
            elif choice == "7":
                valid = app.verify_report(input("Report .txt path: ").strip())
                print("VALID: report is unchanged." if valid else "INVALID: report signature does not match.")
            elif choice == "0":
                print("Goodbye!")
                break
            else:
                print("Choose a number from the menu.")
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
            print("Error:", error)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")
