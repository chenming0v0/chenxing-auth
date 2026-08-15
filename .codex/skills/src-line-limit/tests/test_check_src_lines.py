from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_src_lines.py"


def lines(count: int, trailing_newline: bool = True) -> bytes:
    if count == 0:
        return b""
    content = b"x\n" * count
    return content if trailing_newline else content[:-1]


class SourceLineLimitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test User")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def write(self, relative_path: str, content: bytes) -> None:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def commit_all(self) -> None:
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def run_check(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd or self.repo,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_threshold_boundaries(self) -> None:
        self.write("src/at-300.rs", lines(300))
        self.write("src/at-301.rs", lines(301))
        self.write("src/at-500.rs", lines(500))
        self.write("src/at-501.rs", lines(501))

        result = self.run_check("--all")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("at-300.rs", result.stdout)
        self.assertIn("WARNING src/at-301.rs: 301 lines", result.stdout)
        self.assertIn("WARNING src/at-500.rs: 500 lines", result.stdout)
        self.assertIn("ERROR src/at-501.rs: 501 lines", result.stdout)

    def test_final_line_without_newline_is_counted(self) -> None:
        self.write("src/no-newline.rs", lines(301, trailing_newline=False))

        result = self.run_check("--all")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING src/no-newline.rs: 301 lines", result.stdout)

    def test_binary_file_is_skipped(self) -> None:
        self.write("src/image.bin", b"valid-prefix\0binary-data")

        result = self.run_check("--all")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no matching UTF-8 text files", result.stdout)
        self.assertIn("skipped 1", result.stdout)
        self.assertNotIn("WARNING", result.stdout)
        self.assertNotIn("ERROR src/", result.stdout)

    def test_default_checks_changed_files_while_all_includes_unchanged(self) -> None:
        self.write("src/unchanged.rs", lines(501))
        self.write("src/modified.rs", lines(1))
        self.commit_all()

        self.write("src/modified.rs", lines(301))
        self.write("src/staged.rs", lines(301))
        self.git("add", "src/staged.rs")
        self.write("src/untracked.rs", lines(301))
        nested = self.repo / "tools" / "nested"
        nested.mkdir(parents=True)

        changed = self.run_check(cwd=nested)
        all_files = self.run_check("--all", "--root", str(self.repo))

        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertIn("src/modified.rs", changed.stdout)
        self.assertIn("src/staged.rs", changed.stdout)
        self.assertIn("src/untracked.rs", changed.stdout)
        self.assertNotIn("src/unchanged.rs", changed.stdout)
        self.assertEqual(all_files.returncode, 1, all_files.stderr)
        self.assertIn("ERROR src/unchanged.rs: 501 lines", all_files.stdout)


if __name__ == "__main__":
    unittest.main()
