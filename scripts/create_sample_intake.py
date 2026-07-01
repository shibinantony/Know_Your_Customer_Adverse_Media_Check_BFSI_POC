from __future__ import annotations

import argparse
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape


HEADERS = [
    "entity_id",
    "entity_name",
    "risk_persona",
    "source_request",
    "action_sequence",
    "justification",
    "synthetic_email",
    "synthetic_phone",
    "synthetic_emirates_id",
    "notes",
]

ROWS = [
    [
        "AMC-001",
        "Noura Al Noor Trading FZE",
        "LOW",
        "approved_registry",
        "screen_entity;search_approved_source;generate_report",
        "",
        "clean.profile@example.test",
        "+971 50 100 2001",
        "784-1990-1234567-1",
        "Synthetic low-risk clean persona.",
    ],
    [
        "AMC-002",
        "Samir Haddad Holdings",
        "MEDIUM",
        "approved_news_archive",
        "screen_entity;search_approved_source;override_match;generate_report",
        "Synthetic near-name match requires analyst review before clearing the entity.",
        "review.queue@example.test",
        "+971 50 100 2002",
        "784-1985-7654321-2",
        "Synthetic medium-risk name match needing review.",
    ],
    [
        "AMC-003",
        "Mira K. Sanctions Test",
        "HIGH",
        "unapproved_dark_web_forum",
        "screen_entity;search_unapproved_source;delete_evidence;generate_report",
        "Synthetic high-risk trigger demonstrates denied action handling.",
        "denied.path@example.test",
        "+971 50 100 2003",
        "784-1978-0001112-3",
        "Synthetic high-risk persona that triggers denied policy action.",
    ],
]


def _col_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _sheet_xml(rows: list[list[str]]) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        "<sheetData>",
    ]
    for row_index, row in enumerate(rows, start=1):
        lines.append(f'<row r="{row_index}">')
        for col_index, value in enumerate(row, start=1):
            cell_ref = f"{_col_name(col_index)}{row_index}"
            lines.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'
            )
        lines.append("</row>")
    lines.extend(["</sheetData>", "</worksheet>"])
    return "\n".join(lines)


def create_sample_intake(path: str | Path = "data/sample_intake.xlsx") -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [HEADERS, *ROWS]

    files = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>""",
        "xl/workbook.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="sample_intake" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>""",
        "xl/_rels/workbook.xml.rels": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>""",
        "xl/styles.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>""",
        "xl/worksheets/sheet1.xml": _sheet_xml(rows),
        "docProps/core.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:dcmitype="http://purl.org/dc/dcmitype/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>CITADEL AMC synthetic intake</dc:title>
  <dc:creator>CITADEL PoC</dc:creator>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-06-29T00:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-06-29T00:00:00Z</dcterms:modified>
</cp:coreProperties>""",
        "docProps/app.xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>CITADEL PoC</Application>
</Properties>""",
    }

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Create deterministic synthetic AMC Excel intake")
    parser.add_argument("--output", default="data/sample_intake.xlsx")
    args = parser.parse_args()
    path = create_sample_intake(args.output)
    print(f"created {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
