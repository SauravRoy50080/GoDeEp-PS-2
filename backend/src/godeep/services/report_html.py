"""Deterministic, passive HTML presentation of a verified forensic snapshot."""

import json
from html import escape

from fastapi import HTTPException

EXPORT_VERSION = "1.0.0"
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'; sandbox"
)
STYLE = """
body {font: 16px/1.5 system-ui,sans-serif; color:#172033; margin:2rem auto;
      max-width:1100px; padding:0 1rem; background:white}
h1,h2,h3 {line-height:1.2} h2 {border-bottom:2px solid #ccd4df; padding-bottom:.4rem}
table {border-collapse:collapse; width:100%; margin:1rem 0}
th,td {text-align:left; vertical-align:top; border:1px solid #ccd4df;
       padding:.5rem; overflow-wrap:anywhere} th {width:25%; background:#f3f5f8}
pre {white-space:pre-wrap; overflow-wrap:anywhere; background:#f3f5f8;
     padding:1rem; font:12px/1.5 monospace}
.notice {border-left:4px solid #916300; padding:1rem; background:#fff6df}
@media print {body {margin:0; max-width:none; font-size:11pt}
             pre {font-size:8pt} h2,h3 {break-after:avoid} tr {break-inside:avoid}}
"""


def render(raw, report, limit):
    """No external resources or active links; source strings are always escaped."""
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) or any(
            document.get(key) != value
            for key, value in (
                ("report_id", report.id),
                ("schema_version", report.schema_version),
                ("report_type", "investigation_analysis_snapshot"),
            )
        ):
            raise ValueError("Snapshot identity mismatch")
        if document["sample"]["sha256"] != report.input_sha256:
            raise ValueError("Sample identity mismatch")
        if document["case"]["id"] != report.case_id:
            raise ValueError("Case identity mismatch")
        if document["sample"]["id"] != report.sample_id:
            raise ValueError("Sample identity mismatch")
        if document["schema_version"] not in (1, 2):
            raise ValueError("Unsupported snapshot")
        analyses = document["analyses"]
        captures = document.get("runtime_captures", [])
        if not isinstance(analyses, list) or not isinstance(captures, list):
            raise ValueError("Invalid sources")
        if any(not isinstance(source, dict) for source in analyses + captures):
            raise ValueError("Invalid source record")
        if not 1 <= len(analyses) + len(captures) <= 20:
            raise ValueError("Invalid source count")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise HTTPException(409, "Report snapshot cannot be rendered") from exc

    parts, size = [], 0

    def add(value):
        nonlocal size
        encoded = value.encode("utf-8")
        size += len(encoded)
        if size > limit:
            raise HTTPException(413, "HTML export exceeds configured output bounds")
        parts.append(encoded)

    def text(value):
        # Keep lone surrogate code points visible without emitting invalid UTF-8.
        safe = str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")
        return escape(safe, quote=True)

    def table(values):
        add("<table><tbody>")
        for label, value in values:
            add(f'<tr><th scope="row">{text(label)}</th><td>{text(value)}</td></tr>')
        add("</tbody></table>")

    def block(value):
        try:
            encoded = json.dumps(
                value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
            )
        except (ValueError, TypeError, RecursionError) as exc:
            raise HTTPException(409, "Report snapshot cannot be rendered") from exc
        add("<pre>" + text(encoded) + "</pre>")

    add('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f'<meta http-equiv="Content-Security-Policy" content="{escape(CSP, quote=True)}">')
    add("<title>GoDeEp forensic report</title><style>" + STYLE + "</style></head><body>")
    add("<main><h1>GoDeEp forensic investigation report</h1>")
    add(
        '<p class="notice">Presentation of a selected immutable JSON snapshot. '
        "No analyst sign-off, malware verdict or legal certification is generated. "
        "Source coverage and collector claims retain their original limitations.</p>"
    )
    table(
        [
            ("Report ID", report.id),
            ("Snapshot schema", report.schema_version),
            ("Snapshot generated at", document.get("generated_at")),
            ("Created by", document.get("created_by")),
            ("Source JSON SHA-256", report.artifact_sha256),
            ("HTML renderer", EXPORT_VERSION),
        ]
    )
    for title, key in (
        ("Case", "case"),
        ("Sample and original integrity", "sample"),
        ("Selected sources", "selection"),
        ("Limitations", "limitations"),
    ):
        add("<h2>" + title + "</h2>")
        value = document.get(key)
        if key in {"case", "sample", "selection"} and isinstance(value, dict):
            table((label.replace("_", " ").capitalize(), item) for label, item in value.items())
        else:
            block(value)
    add("<h2>Static and analysis sources</h2>")
    if not analyses:
        add("<p>No analysis jobs selected.</p>")
    for index, source in enumerate(analyses, 1):
        add(f"<section><h3>Analysis source {index}</h3>")
        data = source.get("data")
        table(
            [
                ("Adapter", source.get("adapter")),
                ("Adapter version", source.get("adapter_version")),
                ("Job ID", source.get("job_id")),
                ("Result SHA-256", source.get("result_sha256")),
                (
                    "Recorded coverage",
                    data.get("coverage", "not specified")
                    if isinstance(data, dict)
                    else "not specified",
                ),
            ]
        )
        add("<p>Complete recorded source, including configuration and evidence:</p>")
        block(source)
        add("</section>")
    add("<h2>Imported runtime captures</h2>")
    add(
        "<p>Runtime attribution, timing and isolation are collector assertions; "
        "this export does not independently verify execution.</p>"
    )
    if not captures:
        add("<p>No runtime captures selected.</p>")
    for index, source in enumerate(captures, 1):
        add(f"<section><h3>Runtime source {index}</h3>")
        block(source)
        add("</section>")
    add("<h2>Snapshot extensions</h2>")
    block(
        {
            key: value
            for key, value in document.items()
            if key
            not in {
                "schema_version",
                "report_id",
                "report_type",
                "generated_at",
                "created_by",
                "case",
                "sample",
                "selection",
                "limitations",
                "analyses",
                "runtime_captures",
            }
        }
    )
    add(
        "<footer><p>Keep the original JSON download for byte-level verification. "
        "The source JSON hash does not identify these HTML bytes. "
        "Browser printing changes representation and does not create a signed report."
        "</p></footer></main></body></html>"
    )
    return b"".join(parts)
