"""Invalid labels/vectors and schema differences block research promotion."""

import io
import json
from zipfile import ZipFile

from godeep.evaluation import corpus_audit as audit


def test_invalid_rows_and_label_conflicts_are_preserved_not_repaired():
    result, _, _ = audit.audit(b"a,b,class\n0,1,B\n0,1,S\n?,1,S\n", {})
    assert result["invalid_rows"] == 1 and result["conflicting_vector_groups"] == 1
    assert result["strict_research_import_eligible"] is False
    assert result["production_promotion"].startswith("blocked")


def test_alignment_requires_exact_feature_names_and_orders_before_hashing():
    left = audit.audit(b"a,b,class\n0,1,B\n", {})
    right = audit.audit(b"b,a,class\n1,0,B\n", {})
    assert audit.compare(left, right)["shared_aligned_feature_vectors"] == 1
    unrelated = audit.audit(b"b,c,class\n1,0,B\n", {})
    assert audit.compare(left, unrelated)["shared_aligned_feature_vectors"] is None
    conflicted = audit.audit(b"a,b,class\n0,1,B\n0,1,S\n", {})
    assert audit.compare(conflicted, conflicted)["shared_vectors_with_label_conflicts"] == 1


def test_zip_audit_reads_exact_member_without_extraction(tmp_path, capsys):
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as z:
        z.writestr("features.csv", b"a,class\n1,B\n0,S\n")
    source = tmp_path / "archive.zip"
    source.write_bytes(buffer.getvalue())
    output = tmp_path / "audit.json"
    assert (
        audit.main(["--dataset", str(source), "--member", "features.csv", "--output", str(output)])
        == 0
    )
    result = json.loads(output.read_bytes())
    assert result["training_performed"] is False and result["dataset"]["rows"] == 2
    assert not (tmp_path / "features.csv").exists()
    assert (
        audit.main(["--dataset", str(source), "--member", "features.csv", "--output", str(output)])
        == 2
    )
