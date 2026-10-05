"""Local API regression checks: python -m unittest discover -s tests"""
import unittest
import uuid
from fastapi.testclient import TestClient
import main


class SecureVaultApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.username = "test_" + uuid.uuid4().hex[:12]
        response = cls.client.post("/api/register", json={"username": cls.username, "password": "StrongTestPass!26"})
        assert response.status_code == 200, response.text
        cls.token = response.json()["token"]
        cls.headers = {"X-User": cls.token}

    @classmethod
    def tearDownClass(cls):
        with main.db() as connection:
            rows = connection.execute("SELECT stored FROM files WHERE owner=?", (cls.token,)).fetchall()
            connection.execute("DELETE FROM files WHERE owner=?", (cls.token,))
            connection.execute("DELETE FROM logs WHERE owner=?", (cls.token,))
            connection.execute("DELETE FROM stats WHERE owner=?", (cls.token,))
            connection.execute("DELETE FROM users WHERE id=?", (cls.token,))
        for row in rows:
            (main.VAULT / row["stored"]).unlink(missing_ok=True)
        for suffix in ("private.pem", "public.pem"):
            (main.KEYS / f"{cls.token}.{suffix}").unlink(missing_ok=True)

    def upload(self, name="notes.txt", content=b"SecureVault test bytes", mime="text/plain"):
        response = self.client.post("/api/files", headers=self.headers, files={"file": (name, content, mime)})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id"]

    def test_registration_login_and_dashboard(self):
        response = self.client.post("/api/login", json={"username": self.username, "password": "StrongTestPass!26"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["token"], self.token)
        self.assertEqual(self.client.get("/api/dashboard", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)

    def test_aes_empty_large_wrong_password_and_corrupt_ciphertext(self):
        for name, content in (("empty.bin", b""), ("large.dat", b"0123456789abcdef" * 327680)):
            fid = self.upload(name, content, "application/octet-stream")
            encrypted = self.client.post(f"/api/files/{fid}/encrypt", headers=self.headers, data={"password": "FileSecret!26"})
            self.assertEqual(encrypted.status_code, 200, encrypted.text)
            wrong = self.client.post(f"/api/files/{fid}/decrypt", headers=self.headers, data={"password": "wrong"})
            self.assertEqual(wrong.status_code, 400)
            restored = self.client.post(f"/api/files/{fid}/decrypt", headers=self.headers, data={"password": "FileSecret!26"})
            self.assertEqual(restored.status_code, 200, restored.text)
            stored = self.client.get(f"/api/files/{fid}/download", headers=self.headers)
            self.assertEqual(stored.content, content)
        fid = self.upload("corrupt.txt")
        self.client.post(f"/api/files/{fid}/encrypt", headers=self.headers, data={"password": "FileSecret!26"})
        with main.db() as connection:
            row = connection.execute("SELECT stored FROM files WHERE id=?", (fid,)).fetchone()
        path = main.VAULT / row["stored"]
        blob = bytearray(path.read_bytes()); blob[-1] ^= 0x01; path.write_bytes(blob)
        response = self.client.post(f"/api/files/{fid}/decrypt", headers=self.headers, data={"password": "FileSecret!26"})
        self.assertEqual(response.status_code, 400)

    def test_hash_text_and_files(self):
        text = self.client.post("/api/hash/text", headers=self.headers, json={"text": "abc", "algorithm": "sha256"})
        self.assertEqual(text.json()["hash"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        file_hash = self.client.post("/api/hash/file", headers=self.headers, data={"algorithm": "sha512"}, files={"file": ("picture.png", b"image fixture", "image/png")})
        self.assertEqual(file_hash.status_code, 200)
        self.assertEqual(len(file_hash.json()["hash"]), 128)
        self.assertEqual(self.client.post("/api/hash/text", headers=self.headers, json={"text": "x", "algorithm": "invalid"}).status_code, 400)

    def test_rsa_signature_and_tamper_detection(self):
        fid = self.upload("signed.txt", b"original signed content")
        signed = self.client.post(f"/api/sign/{fid}", headers=self.headers)
        self.assertEqual(signed.status_code, 200, signed.text)
        signature = signed.json()["signature"]
        verified = self.client.post(f"/api/verify/{fid}", headers=self.headers, json={"signature": signature})
        self.assertTrue(verified.json()["valid"])
        with main.db() as connection:
            row = connection.execute("SELECT stored FROM files WHERE id=?", (fid,)).fetchone()
        (main.VAULT / row["stored"]).write_bytes(b"modified content")
        changed = self.client.post(f"/api/verify/{fid}", headers=self.headers, json={"signature": signature})
        self.assertFalse(changed.json()["valid"])

    def test_duplicate_rename_delete_and_logs_export(self):
        fid = self.upload("rename.txt")
        duplicate = self.client.post("/api/files", headers=self.headers, files={"file": ("rename.txt", b"duplicate", "text/plain")})
        self.assertEqual(duplicate.status_code, 409)
        renamed = self.client.patch(f"/api/files/{fid}", headers=self.headers, json={"name": "renamed.txt"})
        self.assertEqual(renamed.status_code, 200)
        exported = self.client.get("/api/logs/export", headers=self.headers)
        self.assertEqual(exported.status_code, 200)
        self.assertIn("File uploaded", exported.text)
        deleted = self.client.delete(f"/api/files/{fid}?secure=true", headers=self.headers)
        self.assertEqual(deleted.status_code, 200)
        names = [entry["name"] for entry in self.client.get("/api/files", headers=self.headers).json()]
        self.assertNotIn("renamed.txt", names)

    def test_password_generator_and_password_change(self):
        generated = self.client.post("/api/password-generator", json={"length": 32, "uppercase": True, "lowercase": True, "numbers": True, "symbols": True})
        self.assertEqual(len(generated.json()["password"]), 32)
        changed = self.client.post("/api/password", headers=self.headers, json={"old_password": "StrongTestPass!26", "new_password": "ChangedPassword!26"})
        self.assertEqual(changed.status_code, 200)
        logged_in = self.client.post("/api/login", json={"username": self.username, "password": "ChangedPassword!26"})
        self.assertEqual(logged_in.status_code, 200)
        restored = self.client.post("/api/password", headers=self.headers, json={"old_password": "ChangedPassword!26", "new_password": "StrongTestPass!26"})
        self.assertEqual(restored.status_code, 200)

    def test_backup_restore_and_invalid_archive(self):
        self.upload("backup-note.txt", b"backup contents")
        self.assertEqual(self.client.post("/api/backup", headers=self.headers).status_code, 200)
        archive = self.client.get("/api/backup/download", headers=self.headers)
        restored = self.client.post("/api/backup/restore", headers=self.headers, files={"file": ("backup.zip", archive.content, "application/zip")})
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertGreaterEqual(restored.json()["restored"], 1)
        self.assertEqual(self.client.post("/api/backup/restore", headers=self.headers, files={"file": ("bad.zip", b"not a zip", "application/zip")}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
