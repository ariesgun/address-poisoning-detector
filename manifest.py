from typing import List

from pydantic import Field
from sentinel.manifest import BaseSchema, MetadataModel, NetworkTag, Severity, Status
from typing_extensions import TypedDict


class Schema(BaseSchema):
    balance_threshold: float = Field(
        title="Balance Threshold", description="Whale Balance Threshold", default=100000.0000
    )
    severity: Severity = Field(title="Severity", description="Severity", default=Severity.MEDIUM)


metadata = MetadataModel(
    name="agun-address-poisoning-detector",
    version="0.1.0",
    status=Status.ACTIVE,
    description="Address Poisoning Detector",
    tags=[
        NetworkTag.EVM,
    ],
    faq=[
        {
            "name": "What is for?",
            "value": "Detect Address poisoning actions",
        }
    ],
)
