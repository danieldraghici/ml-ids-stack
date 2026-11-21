"""Nothing this repository builds, runs or installs floats (R-04).

A tag such as @v4, nginx:1.30 or a bare `pip install x` names whatever it points to on the
day of the run. A commit SHA, an image digest or a file hash cannot move. This test also
catches a placeholder digest someone forgot to fill in, which the linters do not.
"""
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def files(pattern):
    return sorted(p for p in ROOT.glob(pattern) if ".git" not in p.parts)


def rel(p):
    return p.relative_to(ROOT).as_posix()


@pytest.mark.parametrize("path", files("**/Dockerfile*"), ids=rel)
def test_dockerfile_base_images_pinned_by_digest(path):
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", path.read_text(), flags=re.M)
    assert froms, f"{rel(path)} has no FROM line"
    for image in froms:
        assert DIGEST.search(image), f"{rel(path)}: {image} is not pinned by digest"


@pytest.mark.parametrize("path", [ROOT / "compose.yaml", ROOT / "ci" / "compose.yaml", ROOT / "misp" / "compose.override.yaml"], ids=rel)
def test_compose_images_pinned_by_digest(path):
    services = yaml.safe_load(path.read_text())["services"]
    for name, svc in services.items():
        if "build" in svc:      # built here from a Dockerfile, checked above
            continue
        assert DIGEST.search(svc["image"]), f"{rel(path)}: {name} uses {svc['image']}"


@pytest.mark.parametrize("path", files(".github/workflows/*.yml"), ids=rel)
def test_actions_pinned_to_a_commit_sha_with_the_tag_in_a_comment(path):
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)(.*)$", path.read_text(), flags=re.M)
    for ref, comment in uses:
        if ref.startswith("./"):
            continue
        action, _, version = ref.partition("@")
        assert SHA.match(version), f"{rel(path)}: {ref} is not a full commit SHA"
        assert re.search(r"#\s*v?\d", comment), f"{rel(path)}: {ref} has no tag comment"


def test_workflows_start_read_only():
    for path in files(".github/workflows/*.yml"):
        top = yaml.safe_load(path.read_text())
        assert top.get("permissions") == {"contents": "read"}, rel(path)


def test_pre_commit_revisions_frozen_to_shas():
    repos = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())["repos"]
    for repo in repos:
        if repo["repo"] in ("local", "meta"):
            continue
        assert SHA.match(repo["rev"]), f"{repo['repo']} rev {repo['rev']} is not a commit SHA"


def test_dev_container_pinned_by_digest():
    text = (ROOT / ".devcontainer" / "devcontainer.json").read_text()
    conf = json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.M))
    assert DIGEST.search(conf["image"])
    for feature in conf.get("features", {}):
        assert DIGEST.search(feature), feature


def requirements(path):
    """(line, hashes) per requirement, with backslash continuations joined."""
    text = re.sub(r"\\\n", " ", path.read_text())
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append((line.split()[0], re.findall(r"--hash=sha256:([0-9a-f]{64})", line)))
    return out


REQUIREMENTS = [p for p in files("**/requirements*.txt") if "out" not in p.relative_to(ROOT).parts]


@pytest.mark.parametrize("path", REQUIREMENTS, ids=rel)
def test_requirements_pinned_exactly_with_hashes(path):
    reqs = requirements(path)
    assert reqs
    for spec, hashes in reqs:
        assert re.fullmatch(r"[A-Za-z0-9_.\-]+==[0-9][\w.]*", spec), f"{rel(path)}: {spec} is not an exact pin"
        assert hashes, f"{rel(path)}: {spec} has no --hash"


def test_trivy_scans_every_requirements_file():
    """make scan (and the CI job scan) must cover every pinned Python dependency file (R-04)."""
    makefile = (ROOT / "Makefile").read_text()
    line = next(l for l in makefile.splitlines() if "trivy fs" in l)
    pattern = re.search(r"--file-patterns '?pip:([^' ]+)'?", line)
    assert pattern, "make scan has no pip file pattern: Trivy would skip requirements-*.txt"
    files = [p for p in ROOT.rglob("requirements*.txt") if "out" not in p.relative_to(ROOT).parts]
    assert len(files) >= 3
    for f in files:
        assert f.name == "requirements.txt" or re.fullmatch(pattern.group(1), f.name), f"{f} is not scanned"


def test_geoip_databases_match_their_hashes():
    """The committed GeoIP databases are exactly the ones recorded in geoip/SHA256SUMS (R-10)."""
    import hashlib
    lines = [l.split() for l in (ROOT / "geoip" / "SHA256SUMS").read_text().splitlines() if l.strip()]
    assert {n for _, n in lines} == {p.name for p in (ROOT / "geoip").glob("*.mmdb.gz")}
    for digest, name in lines:
        assert hashlib.sha256((ROOT / "geoip" / name).read_bytes()).hexdigest() == digest
    month = re.search(r"^GEOIP_MONTH := (\S+)$", (ROOT / "Makefile").read_text(), flags=re.M).group(1)
    assert all(month in n for _, n in lines)
