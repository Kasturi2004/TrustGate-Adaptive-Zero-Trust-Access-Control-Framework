import { apiRequest } from "./client.ts";
import { getDeviceIdentifier } from "../lib/deviceIdentity.ts";

export class DeviceRecognitionApiError extends Error {
  readonly status: number;

  constructor(status: number) {
    super("Device recognition request failed");
    this.name = "DeviceRecognitionApiError";
    this.status = status;
  }
}

export type DeviceRecognitionStatus = { recognized: boolean };

async function requestStatus(
  path: string,
  method: "GET" | "POST" | "DELETE",
  body?: unknown,
): Promise<DeviceRecognitionStatus> {
  const response = await apiRequest(path, {
    method,
    ...(body === undefined ? {} : { body }),
    headers: { "X-Device-Token": getDeviceIdentifier() },
  });
  if (!response.ok) throw new DeviceRecognitionApiError(response.status);
  const value: unknown = await response.json();
  if (
    typeof value !== "object" ||
    value === null ||
    !("recognized" in value) ||
    typeof value.recognized !== "boolean"
  ) {
    throw new Error("Device recognition response was not recognized");
  }
  return { recognized: value.recognized };
}

export function fetchCurrentDeviceRecognition(): Promise<DeviceRecognitionStatus> {
  return requestStatus("/devices/current", "GET");
}

export function recognizeCurrentDevice(accessRequestId: string): Promise<DeviceRecognitionStatus> {
  return requestStatus("/devices/recognition", "POST", {
    access_request_id: accessRequestId,
  });
}

export function forgetCurrentDevice(): Promise<DeviceRecognitionStatus> {
  return requestStatus("/devices/current/recognition", "DELETE");
}
