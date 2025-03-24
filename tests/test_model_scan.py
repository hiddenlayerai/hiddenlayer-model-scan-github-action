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
def test_model_scan_local_folder(host):
    """Test that scanning a folder of models doesn't break."""
    model_scan.main(
        model_path="tests/models", model_name="github_action_folder_test", api_url=host
    )


@pytest.mark.xfail()
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
            model_path="https://hiddenlayeraitestfiles.blob.core.windows.net/azureml/malicious_model.bin",
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
    if output["detection_count"] > 0:
        found_detection = True

    os.remove("output.json")

    assert found_detection


@pytest.mark.parametrize("host", params)
def test_output_write_fails_non_w_path(host):
    """Test scan model fails if output path is not writable"""

    with pytest.raises(IOError):
        model_scan.main(
            model_path="hf://drhyrum/bert-tiny-torch-vuln",
            api_url=host,
            output_file="/tests.json",
            fail_on_detection=False,
        )


@pytest.mark.parametrize("host", params)
def test_sarif_write_fails_non_w_path(host):
    """Test scan model fails if sarif path is not writable"""

    with pytest.raises(IOError):
        model_scan.main(
            model_path="hf://drhyrum/bert-tiny-torch-vuln",
            api_url=host,
            sarif_file="/tests.json",
            fail_on_detection=False,
        )


@pytest.mark.parametrize("host", params)
def test_sarif_output_no_detections(host):
    """Test SARIF output is correct without detections."""

    output_path = "no_detections_output.sarif"

    model_scan.main(
        model_path="./README.md",
        model_name="README.md",
        api_url=host,
        sarif_file=output_path,
        fail_on_detection=False,
    )

    with open(output_path, "r") as f:
        output = json.load(f)

    os.remove(output_path)

    assert len(output["runs"][0]["results"]) == 0
    assert output["runs"][0]["tool"]["driver"]["name"] == "HiddenLayer Model Scanner"


@pytest.mark.parametrize("host", params)
def test_sarif_output_detections(host):
    """Test SARIF output is correct with detections"""

    output_path = "detections_output.sarif"

    model_scan.main(
        model_path="hf://drhyrum/bert-tiny-torch-vuln",
        api_url=host,
        sarif_file=output_path,
        fail_on_detection=False,
    )

    with open(output_path, "r") as f:
        output = json.load(f)

    os.remove(output_path)

    assert len(output["runs"][0]["results"]) > 0
    assert output["runs"][0]["results"][0]["ruleId"] == "PICKLE_0057_202408"
    assert (
        output["runs"][0]["results"][0]["properties"]["sha256"]
        == "00c0dcab98b14b5b8effa5724cc2b02d01624539460420c0ca13cbd9878da2ce"
    )
    assert output["runs"][0]["results"][0]["properties"]["modelType"] == "pytorch"
    assert output["runs"][0]["results"][0]["properties"]["problem.severity"] == "high"


@pytest.mark.parametrize("host", params)
def test_community_scan(host):
    """Test community Scan with HuggingFace ScanMe repo"""

    model_scan.main(
        model_path="ScanMe/Models",
        api_url=host,
        model_name="GHA Community Scan Test",
        model_version="main",
        community_scan="HUGGING_FACE",
        fail_on_detection=False,
        output_file="output.json",
    )

    with open("output.json", "r") as f:
        output = json.load(f)

    assert len(output) > 0

    valid_result = False
    if output["detection_count"] == 6 and output["file_count"] == 12:
        valid_result = True

    os.remove("output.json")

    assert valid_result
