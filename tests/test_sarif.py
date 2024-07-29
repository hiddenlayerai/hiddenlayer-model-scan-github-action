import pytest
from hiddenlayer.sdk.models import ScanResults
from hiddenlayer.sdk.rest.models import FileInfo

from sarif import SarifV2Output


@pytest.fixture(scope="module")
def scan_results() -> ScanResults:
    return ScanResults(
        scan_id="test",
        status="done",
        start_time=0,
        end_time=1,
        results=FileInfo(
            md5="testmd",
            sha256="testsha",
            type="testfile",
            subtype=["testsub"],
            tlsh="test",
        ),
        detections=[],
        file_path="file:///tmp/file_location",
    )


def test_sarif_no_detections(scan_results: ScanResults):
    """Test SARIF output with no detections"""

    sarif_model = SarifV2Output.from_scan_results([scan_results])

    assert sarif_model.runs[0].results == []


def test_sarif_detections(scan_results: ScanResults):
    scan_results.detections = [
        {
            "description": "test description",
            "message": "test message",
            "severity": "SUSPICIOUS",
        },
        {
            "description": "test description",
            "message": "test message",
            "severity": "MALICIOUS",
        },
    ]

    sarif_model = SarifV2Output.from_scan_results([scan_results])

    assert len(sarif_model.runs[0].results) > 0

    for result in sarif_model.runs[0].results:
        assert result.level in ["error", "warning", "none"]
        assert result.message.text == "test description"
        assert result.rule_id == "test message"
