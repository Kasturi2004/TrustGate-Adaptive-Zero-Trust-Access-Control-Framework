"""Safe device familiarity responses and explicit recognition request."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DeviceRecognitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_request_id: UUID


class DeviceRecognitionStatus(BaseModel):
    recognized: bool
