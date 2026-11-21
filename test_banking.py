"""Run with: python -m unittest -v"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from Crypto.PublicKey import RSA
from banking import BankingProject, encode, money_to_paise, verify


class BankingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = BankingProject(self.temp.name)
        keys = Path(self.temp.name) / "keys"
        keys.mkdir()
        (keys / "private.pem").write_bytes(self.key.export_key())
        (keys / "public.pem").write_bytes(self.key.public_key().export_key())
        self.id = self.app.create_transaction("Alice", "Bob", "500.25")

    def test_original_and_tampered_copy(self):
        self.assertTrue(self.app.verify_transaction(self.id))
        self.assertEqual(self.app.tamper_demo(self.id), (True, False))
        self.assertTrue(self.app.verify_transaction(self.id))

    def test_every_signed_field_is_protected(self):
        row = self.app.rows()[0]
        data = json.loads(row[1])
        for field in data:
            changed = dict(data)
            changed[field] = 999 if field == "amount_paise" else "changed"
            with self.subTest(field=field):
                self.assertFalse(verify(changed, row[2], self.key.public_key()))

    def test_wrong_key_and_changed_signature(self):
        row = self.app.rows()[0]
        data = json.loads(row[1])
        self.assertFalse(verify(data, row[2], RSA.generate(2048).public_key()))
        damaged = bytes([row[2][0] ^ 1]) + row[2][1:]
        self.assertFalse(verify(data, damaged, self.key.public_key()))

    def test_database_tampering_appears_in_report(self):
        row = self.app.rows()[0]
        data = json.loads(row[1])
        data["amount_paise"] = 999999
        with sqlite3.connect(self.app.database) as db:
            db.execute("UPDATE transactions SET payload=? WHERE id=?", (encode(data).decode(), self.id))
        self.assertFalse(self.app.verify_transaction(self.id))
        report = self.app.export_report()
        self.assertIn("Invalid: 1", report.read_text())
        self.assertTrue(self.app.verify_report(report))

    def test_report_tampering(self):
        report = self.app.export_report()
        self.assertTrue(self.app.verify_report(report))
        report.write_bytes(report.read_bytes() + b"Changed")
        self.assertFalse(self.app.verify_report(report))

    def test_invalid_amounts(self):
        for amount in ("0", "-10", "1.001", "NaN", "Infinity", "abc", "1000000001"):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                money_to_paise(amount)
        self.assertEqual(money_to_paise("0.10"), 10)

    def test_key_overwrite_is_blocked(self):
        with self.assertRaises(ValueError):
            self.app.generate_keys()
        self.assertTrue(self.app.verify_transaction(self.id))

    def test_persistence_and_unknown_id(self):
        self.assertTrue(BankingProject(self.temp.name).verify_transaction(self.id))
        with self.assertRaises(ValueError):
            self.app.verify_transaction("unknown")

    def test_bad_account_names(self):
        for sender, receiver in (("", "Bob"), ("Alice", "alice"), ("A\nB", "Bob")):
            with self.assertRaises(ValueError):
                self.app.create_transaction(sender, receiver, "10")

    def test_generate_new_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            app = BankingProject(folder)
            app.generate_keys()
            self.assertEqual(app.key().size_in_bits(), 2048)
            self.assertFalse(app.key().has_private())
            record_id = app.create_transaction("A", "B", "1")
            self.assertTrue(app.verify_transaction(record_id))


if __name__ == "__main__":
    unittest.main()
