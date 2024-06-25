import pytest

import model_scan

params = [
    ("https://api.us.hiddenlayer.ai"),
    pytest.param("http://localhost:8000", marks=pytest.mark.xfail),
]


@pytest.mark.parametrize("host", params)
def test_model_scan_local_file(host):
    """Test that scanning a model doesn't break."""
    model_scan.main(model_path="tests/models/example_model.xgb", api_url=host)


@pytest.mark.parametrize("host", params)
def test_model_scan_s3(host):
    """Test scanning a malicious model breaks."""

    with pytest.raises(SystemExit) as e:
        model_scan.main(
            model_path="s3://hl-oss-integration-tests/example_models/malicious_torch.bin",
            api_url=host,
        )

    assert e.value.code == 1


@pytest.mark.parametrize("host", params)
def test_model_scan_azure(host):
    """Test scanning a malicious model on azure."""

    with pytest.raises(SystemExit) as e:
        model_scan.main(
            model_path="https://dsdemomodelsstorage.blob.core.windows.net/azureml/malicious_model.bin",
            api_url=host,
        )

    assert e.value.code == 1
