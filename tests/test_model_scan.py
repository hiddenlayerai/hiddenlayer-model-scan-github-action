import pytest

import model_scan


def test_model_scan_local_file():
    """Test that scanning a model doesn't break."""
    model_scan.main(model_path="tests/models/example_model.xgb")


def test_model_scan_s3():
    """Test scanning a malicious model breaks."""

    with pytest.raises(SystemExit) as e:
        model_scan.main(
            model_path="s3://hl-oss-integration-tests/example_models/malicious_torch.bin"
        )

    assert e.value.code == 1
