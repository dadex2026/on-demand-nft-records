"""The sealed-secret guard for on-demand-nft-records. Standard library only.

Anything pushed to any branch of this public repository is public at once, so
this runs BEFORE every push: inside the publishing jobs, as the pre-push hook
(.githooks/pre-push), and on GitHub as an alarm (.github/workflows/guard.yml).

It checks every file in every commit about to be pushed, and refuses if:

  1. a path is outside the allowlist below;
  2. any 64-character hex string is a sealed secret: its SHA-256 equals the
     commitment of a day whose window has not closed;
  3. a reveal is for a day whose window has not closed, names no published
     commitment, or does not hash to that commitment;
  4. a commitment record is malformed.

Not caught: a secret written in some other encoding (base64, raw bytes). The
jobs only ever write hex, which is why that is the form checked.

    python tools/guard.py [--now UNIX_SECONDS] [-- REV ...]

REV arguments, after `--`, go to `git rev-list` (for example `origin/master..HEAD`
or `<sha> --not --remotes`). With none, the commit HEAD is checked.
"""
import argparse, fnmatch, hashlib, json, re, subprocess, sys, time

ALLOWED = [
    "README.md", ".gitattributes", ".gitignore",
    ".githooks/pre-push", ".github/workflows/guard.yml",
    "tools/guard.py", "tests/test_guard.py",
    "configs/config-v*.json", "configs/fingerprints.jsonl",
    "records/commitments/g*/d*.json", "records/reveals/g*/d*.json",
    "records/incidents/*.json",
    "contests/*.json", "results/*.json",
]
HEX64 = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
COMMIT_FIELDS = ("offset_group", "day_index", "commitment", "anchor_round", "window_close")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def blobs(revs):
    """(path, blob id) for every file in every commit in revs, deduplicated."""
    commits = git("rev-list", *revs).split() if revs else [git("rev-parse", "HEAD").strip()]
    seen = {}
    for c in commits:
        for line in git("ls-tree", "-r", "-z", c.decode()).split(b"\0"):
            if not line:
                continue
            meta, path = line.split(b"\t", 1)
            seen.setdefault((path.decode("utf-8", "replace"), meta.split()[2].decode()), c.decode()[:12])
    return seen


def allowed(path):
    return any(fnmatch.fnmatchcase(path, pat) for pat in ALLOWED)


def check(revs, now):
    problems, files = [], blobs(revs)
    contents = {key: git("cat-file", "blob", key[1]) for key in files}

    # commitments, from every version of every commitment record being pushed
    commitments = {}
    for (path, _), data in contents.items():
        if fnmatch.fnmatchcase(path, "records/commitments/g*/d*.json"):
            try:
                rec = json.loads(data)
                assert all(k in rec for k in COMMIT_FIELDS)
                commitments[rec["commitment"].lower()] = rec
            except Exception:
                problems.append(f"{path}: malformed commitment record")
    unclosed = {c for c, r in commitments.items() if now < r["window_close"]}

    for (path, blob), data in contents.items():
        where = f"{path} (in commit {files[(path, blob)]})"
        if not allowed(path):
            problems.append(f"{where}: path is not on the allowlist")
        for m in HEX64.finditer(data):
            if hashlib.sha256(bytes.fromhex(m.group().decode())).hexdigest() in unclosed:
                problems.append(f"{where}: contains a SEALED SECRET for a day whose window "
                                f"has not closed")
        if fnmatch.fnmatchcase(path, "records/reveals/g*/d*.json"):
            try:
                rev = json.loads(data)
                c = hashlib.sha256(bytes.fromhex(rev["secret"])).hexdigest()
            except Exception:
                problems.append(f"{where}: malformed reveal"); continue
            rec = commitments.get(c)
            if rec is None:
                problems.append(f"{where}: reveal matches no published commitment")
            elif now < rec["window_close"]:
                problems.append(f"{where}: reveal for a day whose window has not closed")
            elif (rec["offset_group"], rec["day_index"]) != (rev.get("offset_group"), rev.get("day_index")):
                problems.append(f"{where}: reveal names a different day from its commitment")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--now", type=float, default=None, help="unix seconds (default: the clock)")
    ap.add_argument("revs", nargs="*")
    a = ap.parse_args(argv)
    problems = check(a.revs, time.time() if a.now is None else a.now)
    for p in problems:
        print("REFUSED", p)
    if problems:
        print(f"\nguard: {len(problems)} problem(s); nothing may be pushed")
        return 1
    print("guard: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
