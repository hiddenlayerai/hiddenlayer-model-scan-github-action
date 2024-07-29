import os
import pytest
import json

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


@pytest.mark.parametrize("host", params)
def test_model_scan_huggingface(host):
    """Test scanning model from huggingface"""

    with pytest.raises(SystemExit) as e:
        model_scan.main(
            model_path="hf://drhyrum/bert-tiny-torch-vuln",
            api_url=host,
        )

    print(e)

    assert e.value.code == 1


@pytest.mark.parametrize("host", params)
def test_output_path_not_json(host):
    """Test scanning model from huggingface"""

    with pytest.raises(ValueError):
        model_scan.main(
            model_path="hf://drhyrum/bert-tiny-torch-vuln",
            api_url=host,
            output_file="file.txt",
        )


@pytest.mark.parametrize("host", params)
def test_output_path_is_dir(host):
    """Test scanning model from huggingface"""

    with pytest.raises(ValueError):
        model_scan.main(
            model_path="hf://drhyrum/bert-tiny-torch-vuln",
            api_url=host,
            output_file="./tests",
            fail_on_detection=False,
        )


@pytest.mark.parametrize("host", params)
def test_output_file(host):
    """Test scanning model from huggingface"""

    model_scan.main(
        model_path="hf://drhyrum/bert-tiny-torch-vuln",
        api_url=host,
        output_file="output.json",
        fail_on_detection=False,
    )

    with open("output.json", "r") as f:
        output = json.load(f)

    assert len(output) > 0

    found_detection = False
    for file in output:
        if len(file["detections"]) > 0:
            found_detection = True

    os.remove("output.json")

    assert found_detection
