"""The risk register stays honest (every risk row, course Session 1).

RISK-REGISTER.md is parsed as written. A row may claim Implemented or Verified only
if every evidence path exists in the branch, scores must follow the course scales,
and RISK-REGISTER.xlsx (the course template) must carry the same IDs, scores and
statuses as the Markdown.
"""
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MD = (ROOT / "RISK-REGISTER.md").read_text(encoding="utf-8")
STATUSES = {"Open", "Implemented", "Verified", "Accepted"}
REGISTERS = {"Operational", "Internal", "External"}


def parse_md(text):
    rows = []
    for block in re.split(r"\n(?=## R-\d\d )", text)[1:]:
        head = re.match(r"## (R-\d\d) \((\w+)\): (.+)", block)
        field = lambda name: re.search(rf"- \*\*{re.escape(name)}:\*\* (.*)", block).group(1)
        inh = re.match(r"L(\d) x I(\d) = (\d+)", field("Inherent"))
        res = re.match(r"L(\d) x I(\d) = (\d+)", field("Residual"))
        rows.append({
            "id": head.group(1), "reg": head.group(2), "asset": head.group(3),
            "L": int(inh.group(1)), "I": int(inh.group(2)), "inherent": int(inh.group(3)),
            "RL": int(res.group(1)), "RI": int(res.group(2)), "residual": int(res.group(3)),
            "why": field("Why the score drops"),
            "evidence": re.findall(r"`([^`]+)`", field("Evidence")),
            "status": field("Owner / status").rsplit("/", 1)[1].strip(),
        })
    return rows


RISKS = parse_md(MD)


def xlsx_rows(path):
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    z = zipfile.ZipFile(path)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        shared = ["".join(t.text or "" for t in si.iter(f"{{{ns['m']}}}t"))
                  for si in ET.fromstring(z.read("xl/sharedStrings.xml"))]
    names = [s.get("name") for s in ET.fromstring(z.read("xl/workbook.xml")).find("m:sheets", ns)]
    sheet = ET.fromstring(z.read(f"xl/worksheets/sheet{names.index('Risk Register') + 1}.xml"))
    rows = {}
    for row in sheet.iter(f"{{{ns['m']}}}row"):
        cells = {}
        for c in row:
            col = re.match(r"[A-Z]+", c.get("r")).group(0)
            v, t = c.find("m:v", ns), c.get("t")
            if t == "inlineStr":
                cells[col] = "".join(x.text or "" for x in c.iter(f"{{{ns['m']}}}t"))
            elif v is not None and c.find("m:f", ns) is None:
                cells[col] = shared[int(v.text)] if t == "s" else v.text
        if re.fullmatch(r"R-\d\d", cells.get("A", "")):
            rows[cells["A"]] = cells
    return rows


def test_ids_are_sequential_and_unique():
    assert [r["id"] for r in RISKS] == [f"R-{i:02d}" for i in range(1, len(RISKS) + 1)]


def test_five_to_ten_rows():
    assert 5 <= len(RISKS) <= 10


def test_every_register_is_covered():
    assert {r["reg"] for r in RISKS} == REGISTERS


@pytest.mark.parametrize("risk", RISKS, ids=lambda r: r["id"])
def test_row_is_well_formed(risk):
    assert risk["status"] in STATUSES
    for key in ("L", "I", "RL", "RI"):
        assert 1 <= risk[key] <= 5, key
    assert risk["inherent"] == risk["L"] * risk["I"]
    assert risk["residual"] == risk["RL"] * risk["RI"]
    assert risk["residual"] <= risk["inherent"], "residual above inherent"
    assert risk["evidence"], "no evidence listed"
    assert risk["why"], "the residual drop is not defended"


@pytest.mark.parametrize("risk", RISKS, ids=lambda r: r["id"])
def test_summary_table_matches_section(risk):
    line = re.search(rf"^\| {risk['id']} \|.*$", MD, flags=re.M).group(0)
    cells = [c.strip() for c in line.strip("|").split("|")]
    assert cells[1] == risk["reg"]
    assert cells[3].startswith(f"{risk['inherent']} ") and cells[4].startswith(f"{risk['residual']} ")
    assert cells[5] == risk["status"]


@pytest.mark.parametrize("risk", RISKS, ids=lambda r: r["id"])
def test_claimed_evidence_exists(risk):
    if risk["status"] not in ("Implemented", "Verified"):
        pytest.skip(f"{risk['id']} is {risk['status']}")
    missing = [p for p in risk["evidence"]
               if not (list(ROOT.glob(p)) if any(c in p for c in "*?[") else (ROOT / p).exists())]
    assert not missing, f"{risk['id']} is {risk['status']} but evidence is missing: {missing}"


def test_xlsx_matches_markdown():
    sheet = xlsx_rows(ROOT / "RISK-REGISTER.xlsx")
    assert sorted(sheet) == [r["id"] for r in RISKS]
    for r in RISKS:
        row = sheet[r["id"]]
        assert row.get("B") == r["reg"], r["id"]
        assert [int(float(row[c])) for c in "GHKL"] == [r["L"], r["I"], r["RL"], r["RI"]], r["id"]
        assert row.get("P") == r["status"], r["id"]
