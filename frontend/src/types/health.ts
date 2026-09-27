export type HealthResponse = {
  status: "ok";
};

export type HealthCheckState =
  { kind: "loading" } | { kind: "ok" } | { kind: "error"; message: string };
