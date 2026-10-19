"""Validated sample registration with compensating cleanup on failed DB commit."""

from pathlib import Path

from godeep.analysis.static.archive import validate_archive
from godeep.persistence.models import AuditEvent, Sample
from godeep.services.cases import require_case


def register_sample(
    factory,
    store,
    settings,
    case_id,
    sample_id,
    original_name,
    staged: Path,
    sha256: str,
    size_bytes: int,
) -> Sample:
    validate_archive(staged, settings)
    destination = None
    try:
        with factory.begin() as session:
            require_case(session, case_id)
            key, destination = store.publish(staged, sample_id)
            sample = Sample(
                id=sample_id,
                case_id=case_id,
                original_name=original_name,
                sha256=sha256,
                size_bytes=size_bytes,
                storage_key=key,
            )
            session.add(sample)
            session.add(
                AuditEvent(
                    case_id=case_id,
                    action="sample.registered",
                    subject_id=sample_id,
                    details={"sha256": sha256, "size_bytes": size_bytes},
                )
            )
        return sample
    except BaseException:
        if destination is not None:
            destination.unlink(missing_ok=True)
        raise
