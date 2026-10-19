"""Bounded archive inventory adapter. No Android code is executed or extracted."""

from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from godeep.integrations.analyzers.common import prepare_snapshot

NAME = "archive_inventory"
VERSION = "1.0.0"


def analyze(original: Path, snapshot: Path, expected_hash: str, config: dict):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    with ZipFile(snapshot) as archive:
        members = archive.infolist()
        files = [m for m in members if not m.is_dir()]
        extensions = Counter(Path(m.filename).suffix.lower()[:16] or "[none]" for m in files)
        dex = [m.filename for m in files if m.filename.lower().endswith(".dex")]
        native = [
            m.filename
            for m in files
            if m.filename.startswith("lib/") and m.filename.lower().endswith(".so")
        ]
        return {
            "schema_version": 1,
            "adapter": NAME,
            "adapter_version": VERSION,
            "input_sha256": expected_hash,
            "input_size_bytes": size,
            "observations": {
                "entry_count": len(members),
                "file_count": len(files),
                "declared_uncompressed_bytes": sum(m.file_size for m in files),
                "dex_count": len(dex),
                "native_library_count": len(native),
                "dex_paths": [name[:256] for name in dex[:100]],
                "native_library_paths": [name[:256] for name in native[:100]],
                "paths_truncated": len(dex) > 100
                or len(native) > 100
                or any(len(n) > 256 for n in dex + native),
                "top_extensions": dict(extensions.most_common(30)),
                "manifest_present": True,
            },
            "limitations": [
                "ZIP metadata inventory only; no manifest or DEX parsing",
                "No signature verification, malware verdict, risk score or runtime execution",
                "ZIP sizes are declared metadata, not verified decompression results",
            ],
        }
