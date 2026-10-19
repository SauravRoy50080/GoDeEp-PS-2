"""Local original-evidence store; opaque IDs prevent client-controlled paths."""

import os
import tempfile
from pathlib import Path


class LocalEvidenceStore:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def stage(self):
        staging = self.root / "staging"
        staging.mkdir(parents=True, exist_ok=True)
        return tempfile.NamedTemporaryFile(
            prefix="intake-", suffix=".part", dir=staging, delete=False
        )

    def publish(self, staged: Path, sample_id: str) -> tuple[str, Path]:
        # sample_id comes exclusively from a server-generated UUID.
        key = f"originals/{sample_id}.apk"
        destination = self.root / key
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged, destination)
        return key, destination
