"""A complete demonstration in a temporary folder; leaves your real data alone."""
import tempfile
from banking import BankingProject


def main():
    with tempfile.TemporaryDirectory() as folder:
        app = BankingProject(folder)
        print("PROJECT 11: SECURE BANKING TRANSACTIONS")
        app.generate_keys()
        print("1. Generated 2048-bit RSA keys.")
        record_id = app.create_transaction("Alice", "Bob", "500.00")
        print("2. Signed and stored Alice -> Bob: INR 500.00.")
        print("3. Original signature valid:", app.verify_transaction(record_id))
        original, changed = app.tamper_demo(record_id)
        print("4. Copy changed to INR 600.00; signature valid:", changed)
        report = app.export_report()
        print("5. Exported report; report signature valid:", app.verify_report(report))
        report.write_bytes(report.read_bytes() + b"Tampered report\n")
        print("6. Modified report; report signature valid:", app.verify_report(report))
        print("Demo complete. Temporary demo data is removed automatically.")


if __name__ == "__main__":
    main()
