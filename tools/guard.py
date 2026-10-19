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
  4. a commitment record is malformed;
  5. records/memo-address.jsonl is not append-only: in any commit, it is not
     its parent's version followed by whole new lines, or it is deleted, or a
     line is not {"address", "from_day"} with from_day rising.

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
    "records/memo-address.jsonl",
    "contests/*.json", "results/*.json",
    "verifier/index.html",
]
MEMO_ADDRESS = "records/memo-address.jsonl"
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


def at(rev, path):
    """The file's bytes in a commit, or None where it does not exist."""
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def memo_address_problems(revs):
    """Every commit in revs against each of its parents: the memo address file
    only ever grows by whole lines, and every line is a well-formed entry."""
    problems = []
    commits = git("rev-list", *revs).split() if revs else [git("rev-parse", "HEAD").strip()]
    for c in (c.decode() for c in commits):
        new = at(c, MEMO_ADDRESS)
        for p in git("rev-list", "--parents", "-n", "1", c).split()[1:]:
            old = at(p.decode(), MEMO_ADDRESS)
            if old is None:
                continue
            if new is None:
                problems.append(f"{MEMO_ADDRESS} (in commit {c[:12]}): deleted; it is append-only")
            elif not new.startswith(old):
                problems.append(f"{MEMO_ADDRESS} (in commit {c[:12]}): an earlier line changed or "
                                f"was removed; it is append-only")
        if new is None:
            continue
        if not new.endswith(b"\n"):
            problems.append(f"{MEMO_ADDRESS} (in commit {c[:12]}): does not end with a whole line")
        last = None
        for n, raw in enumerate(new.split(b"\n")[:-1], start=1):
            try:
                e = json.loads(raw)
                ok = (set(e) == {"address", "from_day"} and isinstance(e["address"], str)
                      and isinstance(e["from_day"], int) and (last is None or e["from_day"] > last))
            except Exception:
                ok = False
            if not ok:
                problems.append(f"{MEMO_ADDRESS} (in commit {c[:12]}) line {n}: not "
                                f'{{"address", "from_day"}} with from_day after the line before')
                break
            last = e["from_day"]
    return problems


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
    return problems + memo_address_problems(revs)


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
