"""Bounded archive inventory adapter. No Android code is executed or extracted."""

import hashlib
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from godeep.analysis.static.archive import validate_archive
from godeep.core.config import Settings

NAME = "archive_inventory"
VERSION = "1.0.0"


class AdapterFailure(Exception):
    pass


def analyze(original: Path, snapshot: Path, expected_hash: str, config: dict):
    settings = Settings(
        _env_file=None, **{k: v for k, v in config.items() if k in Settings.model_fields}
    )
    digest = hashlib.sha256()
    size = 0
    with original.open("rb") as source, snapshot.open("xb") as destination:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise AdapterFailure("input_size_exceeded")
            digest.update(chunk)
            destination.write(chunk)
    if digest.hexdigest() != expected_hash:
        raise AdapterFailure("input_integrity_mismatch")
    validate_archive(snapshot, settings)
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
