"""Tests for tools/guard.py, each in a throwaway Git repository.

    python -m unittest discover -s tests -v
"""
import hashlib, json, os, pathlib, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import guard  # noqa: E402

SECRET = hashlib.sha256(b"TEST ONLY guard secret").hexdigest()
COMMIT = hashlib.sha256(bytes.fromhex(SECRET)).hexdigest()
CLOSE = 1_900_000_000


def record(day=21000, commitment=COMMIT):
    return {"offset_group": -18000, "day_index": day, "commitment": commitment,
            "anchor_round": 123, "memo_signature": "x", "window_close": CLOSE}


class Guard(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.old = os.getcwd()
        os.chdir(self.dir.name)
        for cmd in (["init", "-q", "-b", "master"], ["config", "user.email", "t@t"],
                    ["config", "user.name", "t"], ["config", "core.autocrlf", "false"]):
            subprocess.run(["git", *cmd], check=True)

    def tearDown(self):
        os.chdir(self.old)
        self.dir.cleanup()

    def commit(self, files):
        for path, content in files.items():
            p = pathlib.Path(path); p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        subprocess.run(["git", "add", "-A"], check=True)
        subprocess.run(["git", "commit", "-q", "-m", "t"], check=True)

    def problems(self, now, revs=()):
        return guard.check(list(revs), now)

    def test_clean_commitment_passes(self):
        self.commit({"README.md": "x", "records/commitments/g-18000/d21000.json": record()})
        self.assertEqual(self.problems(CLOSE - 10), [])

    def test_sealed_secret_anywhere_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "results/1.json": {"note": f"oops {SECRET}"}})
        p = self.problems(CLOSE - 10)
        self.assertTrue(any("SEALED SECRET" in x for x in p), p)

    def test_secret_in_upper_case_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "results/1.json": {"note": SECRET.upper()}})
        self.assertTrue(any("SEALED SECRET" in x for x in self.problems(CLOSE - 10)))

    def test_secret_in_an_earlier_commit_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": record()})
        base = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        self.commit({"results/1.json": {"note": SECRET}})
        self.commit({"results/1.json": {"note": "removed"}})
        p = self.problems(CLOSE - 10, [f"{base}..HEAD"])
        self.assertTrue(any("SEALED SECRET" in x for x in p), p)

    def test_early_reveal_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "records/reveals/g-18000/d21000.json": {"offset_group": -18000, "day_index": 21000, "secret": SECRET}})
        p = self.problems(CLOSE - 10)
        self.assertTrue(any("not closed" in x for x in p), p)

    def test_reveal_after_close_passes(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "records/reveals/g-18000/d21000.json": {"offset_group": -18000, "day_index": 21000, "secret": SECRET}})
        self.assertEqual(self.problems(CLOSE + 10), [])

    def test_reveal_without_commitment_is_refused(self):
        self.commit({"records/reveals/g-18000/d21000.json": {"offset_group": -18000, "day_index": 21000, "secret": SECRET}})
        self.assertTrue(any("no published commitment" in x for x in self.problems(CLOSE + 10)))

    def test_reveal_for_the_wrong_day_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "records/reveals/g-18000/d21001.json": {"offset_group": -18000, "day_index": 21001, "secret": SECRET}})
        self.assertTrue(any("different day" in x for x in self.problems(CLOSE + 10)))

    def test_path_outside_allowlist_is_refused(self):
        self.commit({"secrets/day.txt": "x"})
        self.assertTrue(any("allowlist" in x for x in self.problems(CLOSE)))

    def test_malformed_commitment_is_refused(self):
        self.commit({"records/commitments/g-18000/d21000.json": {"commitment": COMMIT}})
        self.assertTrue(any("malformed" in x for x in self.problems(CLOSE)))

    def test_commitment_itself_is_not_mistaken_for_a_secret(self):
        self.commit({"records/commitments/g-18000/d21000.json": record(),
                     "results/1.json": {"commitment": COMMIT}})
        self.assertEqual(self.problems(CLOSE - 10), [])

    def test_exit_code(self):
        self.commit({"secrets/day.txt": "x"})
        self.assertEqual(guard.main(["--now", str(CLOSE)]), 1)


if __name__ == "__main__":
    unittest.main()
