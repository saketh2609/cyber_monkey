
import tempfile
import unittest
from pathlib import Path

from tools.file_tools import (
    read_file,
    write_file,
    delete_file,
)


class FileToolSecurityTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_read_file(self):
        target = self.root / "notes.txt"
        target.write_text("hello", encoding="utf-8")

        self.assertEqual(read_file(target, {"path": "notes.txt"}), "hello")

    def test_oversized_read_blocked(self):
        target = self.root / "large.txt"
        target.write_text("x" * 1_000_001, encoding="utf-8")

        with self.assertRaises(ValueError):
            read_file(target, {"path": "large.txt"})

    def test_oversized_write_blocked(self):
        target = self.root / "large.txt"

        with self.assertRaises(ValueError):
            write_file(
                target,
                {"path": "large.txt", "content": "x" * 1_000_001},
            )

        self.assertFalse(target.exists())

    def test_delete_file(self):
        target = self.root / "delete.txt"
        target.write_text("delete me", encoding="utf-8")

        delete_file(target, {"path": "delete.txt"})

        self.assertFalse(target.exists())

    def test_symlink_read_blocked(self):
        outside = self.root / "outside.txt"
        outside.write_text("private", encoding="utf-8")
        link = self.root / "link.txt"

        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable on this system.")

        with self.assertRaises(PermissionError):
            read_file(link, {"path": "link.txt"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
