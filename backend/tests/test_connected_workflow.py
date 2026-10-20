"""Cross-module regression: registered adapters, captures, comparisons and reports."""

import io
from zipfile import ZipFile

from android_fixtures import MANIFEST, binary_manifest
from test_dex_calls import code_fixture
from test_runtime_captures import trace

from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS
from godeep.workers.runner import run_once


def upload(client, case, xml=MANIFEST):
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest(xml))
        archive.writestr("classes.dex", code_fixture()[0])
        archive.writestr("assets/config.json", b'{"endpoint":"https://example.org/path"}')
    response = client.post(
        f"/api/v1/cases/{case}/samples",
        content=buffer.getvalue(),
        headers={"X-Filename": "connected.apk", "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_all_registered_adapters_to_combined_snapshot_and_comparison(intake):
    client, app, _ = intake
    case = client.post("/api/v1/cases", json={"name": "Connected workflow"}).json()["id"]
    sample = upload(client, case)
    jobs = {}
    assert {item["name"] for item in client.get("/api/v1/analyzers").json()} == set(
        ADAPTER_VERSIONS
    )
    for adapter, version in ADAPTER_VERSIONS.items():
        response = client.post(
            f"/api/v1/cases/{case}/analyses", json={"sample_id": sample["id"], "adapter": adapter}
        )
        assert response.status_code == 202, response.text
        job = response.json()
        assert run_once(app.state.sessions, app.state.settings)
        base = f"/api/v1/cases/{case}/analyses/{job['id']}"
        assert client.get(base).json()["status"] == "completed", adapter
        result = client.get(base + "/result").json()
        assert result["data"]["adapter_version"] == version
        assert result["input_sha256"] == sample["sha256"]
        jobs[adapter] = job["id"]
    sample_base = f"/api/v1/cases/{case}/samples/{sample['id']}"
    capture = client.post(sample_base + "/runtime-captures", json=trace(sample["sha256"]))
    assert capture.status_code == 201, capture.text
    timeline = client.post(
        sample_base + "/runtime-timeline", json={"capture_ids": [capture.json()["id"]]}
    )
    assert timeline.status_code == 200 and timeline.json()["total"] == 3
    report = client.post(
        sample_base + "/reports",
        json={"job_ids": list(jobs.values()), "capture_ids": [capture.json()["id"]]},
    )
    assert report.status_code == 201, report.text
    document = client.get(sample_base + f"/reports/{report.json()['id']}/download").json()
    assert document["schema_version"] == 2 and len(document["analyses"]) == len(jobs)
    assert document["runtime_captures"][0]["data"]["input_sha256"] == sample["sha256"]
    assert document["runtime_captures"][0]["attribution"] == "collector_asserted_not_verified"
    second = upload(
        client, case, MANIFEST.replace('android:debuggable="true"', 'android:debuggable="false"')
    )
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": second["id"], "adapter": "static_review"},
    ).json()
    run_once(app.state.sessions, app.state.settings)
    comparison = client.post(
        f"/api/v1/cases/{case}/comparisons",
        json={"left_job_id": jobs["static_review"], "right_job_id": job["id"]},
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["categories"]["application_flags"]["counts"]["changed"] == 1


def test_streamed_upload_openapi_exposes_resolvable_contract(intake):
    client, _, _ = intake
    document = client.get("/openapi.json").json()
    route = document["paths"]["/api/v1/cases/{case_id}/samples/{sample_id}/runtime-captures"][
        "post"
    ]
    assert (
        route["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        == "#/components/schemas/RuntimeTrace"
    )
    schemas = document["components"]["schemas"]
    assert schemas["RuntimeTrace"]["properties"]["events"]["maxItems"] == 2000

    def inspect(value):
        if isinstance(value, dict):
            if "$ref" in value:
                assert value["$ref"].startswith("#/components/schemas/")
                assert value["$ref"].split("/")[-1] in schemas
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    inspect(document)
