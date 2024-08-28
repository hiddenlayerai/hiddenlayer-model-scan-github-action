from pydantic import BaseModel, ConfigDict, Field
from typing import List, Self
from enum import Enum
from datetime import datetime
from typing import Optional

from hiddenlayer.sdk.models import ScanResults


class SarifLevel(str, Enum):
    NONE = ("none",)
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


class SarifV2RunMessage(BaseModel):
    text: str


class SarifV2RunProperties(BaseModel):
    sha256: str
    model_type: str = Field(serialization_alias="modelType")
    model_subtype: List[str] = Field(serialization_alias="modelSubType")

    model_config = ConfigDict(protected_namespaces=())


class SarifV2FileLocation(BaseModel):
    uri: str


class SarifV2ArtifactPhysicalLocation(BaseModel):
    artifact_location: SarifV2FileLocation = Field(
        serialization_alias="artifactLocation"
    )


class SarifV2ArtifactLocation(BaseModel):
    physical_location: SarifV2ArtifactPhysicalLocation = Field(
        serialization_alias="physicalLocation"
    )


class SarifV2RunResult(BaseModel):
    rule_id: str = Field(serialization_alias="ruleId")
    level: SarifLevel
    message: SarifV2RunMessage
    locations: List[SarifV2ArtifactLocation]
    properties: SarifV2RunProperties


class SarifV2ToolDriver(BaseModel):
    name: str
    version: str


class SarifV2Tool(BaseModel):
    driver: SarifV2ToolDriver


class SarifV2AutomationDetails(BaseModel):
    id: str


class SarifV2Run(BaseModel):
    tool: SarifV2Tool
    results: List[SarifV2RunResult]
    automation_details: Optional[SarifV2AutomationDetails] = Field(
        serialization_alias="automationDetails"
    )


class SarifV2Output(BaseModel):
    version: str
    runs: List[SarifV2Run]
    sarif_schema: str = Field(serialization_alias="$schema")

    @classmethod
    def from_scan_results(
        cls, scan_results: List[ScanResults], run_id: Optional[str] = None
    ) -> Self:
        if run_id and not run_id.endswith("/"):
            run_id = f"{run_id}/"

        sarif_output = cls(
            version="2.1.0",
            sarif_schema="https://json.schemastore.org/sarif-2.1.0.json",
            runs=[
                SarifV2Run(
                    tool=SarifV2Tool(
                        driver=SarifV2ToolDriver(
                            name="HiddenLayer Model Scanner",
                            version="24.8.0",
                        )
                    ),
                    automation_details=SarifV2AutomationDetails(
                        id=run_id
                        or f"modelscan-run-{datetime.now().strftime('%Y%m%dT%H%M%S')}/"
                    ),
                    results=[],
                )
            ],
        )

        for scan_result in scan_results:
            for detection in scan_result.detections:
                severity = detection.get("severity", "")

                match severity:
                    case "SUSPICIOUS":
                        sarif_level = SarifLevel.WARNING
                    case "MALICIOUS":
                        sarif_level = SarifLevel.ERROR
                    case _:
                        sarif_level = SarifLevel.NONE

                sarif_output.runs[0].results.append(
                    SarifV2RunResult(
                        rule_id=detection.get("message", ""),
                        level=sarif_level,
                        message=SarifV2RunMessage(
                            text=detection.get("description", "")
                        ),
                        properties=SarifV2RunProperties(
                            sha256=scan_result.results.sha256 or "",
                            model_type=scan_result.results.type or "",
                            model_subtype=scan_result.results.subtype or [],
                        ),
                        locations=[
                            SarifV2ArtifactLocation(
                                physical_location=SarifV2ArtifactPhysicalLocation(
                                    artifact_location=SarifV2FileLocation(
                                        uri=scan_result.file_path or ""
                                    )
                                )
                            )
                        ],
                    )
                )

        return sarif_output
