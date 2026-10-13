# Device health assessment: behavior and compatibility notes

## Existing behavior before posture assessment

- `services/context/collector.py` reads the HTTP request scheme/proxy metadata and the automatically supplied `User-Agent`. It calls `services/context/health.py` to classify transport plus parsed browser/OS support as `HEALTHY`, `PARTIAL`, or `UNHEALTHY`.
- The employee portal does not send health values. Request context is server-derived; request-body health fields are ignored. `is_connection_secure` honors HTTPS directly, trusted proxies only when configured, and an explicit local-only loopback override.
- `schemas/trust.py` accepts the three normalized health strings. `services/trust_engine.py` maps them to 100, 60, and 10 points. The active policy weights this factor at 0.30. `context_signals.device_health_raw` is stored under a database CHECK constraint with the same three values. Admin investigations display the stored string.
- The existing health evaluator is a prototype browser/transport signal, not endpoint posture evidence. The module and supported-browser YAML already document that it cannot verify OS patching, endpoint protection, encryption, firewall, management, integrity, or compromise.

## Compatibility requirements for the first posture assessment

- Keep the access evaluation request and response, resource IDs, policy thresholds, MFA challenge/redemption behavior, and authorization checks unchanged.
- Keep historical context rows readable and preserve the three existing values. Add `unknown` as a new persisted signal via a forward-only migration; do not rewrite historical rows as if they were posture evidence.
- Keep the existing trust factor name and policy weight. Map unavailable or incomplete posture to an explicit `unknown` value with zero normalized trust points, never to `healthy`; this can make existing outcomes more restrictive but cannot silently raise trust.
- Keep transport security as a separate context datum. Neither HTTP nor browser/OS user-agent information will be used as device posture evidence.
- No trusted OS/device-management/EDR evidence source exists in this repository. The production provider must therefore report all posture checks as unknown. Test-only providers may exercise validated evidence paths, but client input must not be able to instantiate or override them.

## Initial scoring and classification design

The five configured weights total 100 points (25 OS/patch, 25 endpoint protection, 20 disk encryption, 15 firewall, 15 integrity/management). A validated PASS earns its configured points; validated FAIL, UNKNOWN, stale, invalid, malformed, or wrong-device evidence earns zero. The score is the sum of earned points, so unknown evidence cannot become a passing score through denominator renormalization. No valid observations yields `score = null`.

Weights are configurable through `DEVICE_HEALTH_OS_PATCH_WEIGHT`, `DEVICE_HEALTH_ENDPOINT_PROTECTION_WEIGHT`, `DEVICE_HEALTH_DISK_ENCRYPTION_WEIGHT`, `DEVICE_HEALTH_FIREWALL_WEIGHT`, and `DEVICE_HEALTH_INTEGRITY_MANAGEMENT_WEIGHT`; startup validation requires their sum to remain 100. `DEVICE_HEALTH_HEALTHY_THRESHOLD` defaults to 80, `DEVICE_HEALTH_UNHEALTHY_THRESHOLD` to 40, and `DEVICE_HEALTH_EVIDENCE_MAX_AGE_SECONDS` to 86400.

OS/patch and endpoint protection are mandatory. A validated failure in either yields UNHEALTHY even when other evidence is missing. Otherwise HEALTHY requires complete fresh, authentic, correctly bound evidence, all mandatory checks passing, and a score at or above the configured healthy threshold. With incomplete evidence, classify PARTIAL. With complete evidence, classify UNHEALTHY below the configured unhealthy threshold; other complete but non-healthy assessments remain PARTIAL. Mandatory failure takes precedence over missing evidence.

The provider and evidence-authenticator are server-side interfaces. The default provider returns no evidence, and the default authenticator accepts none. Production consequently reports UNKNOWN/PARTIAL until a real integration supplies authenticated, fresh, device-bound observations.

The browser's existing `X-Device-Token` is only a client-held identifier whose database key is HMACed; it is not hardware identity or attestation. A future evidence adapter must securely associate its own authenticated device identity with this server-side binding before its observations can validate.

The trust factor receives the assessment's earned-points score, except a failed mandatory check sends a `0.00` risk score even if other passing checks produce a higher audit score. This ensures mandatory failure cannot receive device-health trust points. No evidence means a null assessment score and zero normalized trust points. The persisted legacy signal is `unknown` for incomplete assessment, `partially_healthy` for complete evidence below the healthy threshold, and `healthy`/`unhealthy` for the corresponding verified outcomes. The admin API adds an optional assessment version marker; older records remain labeled as legacy browser/transport signals.

## Current provider and evidence status

No OS management, EDR, endpoint-security, disk-encryption, firewall, hardware-attestation, or device-management connector is configured. The default provider emits five `UNKNOWN` observations with `provider_unavailable`; none of the five checks currently uses real endpoint evidence. The default verifier rejects every observation. Test-only providers and verifiers exercise assessment paths without enabling production claims.

The provider and verifier interfaces receive the server-derived opaque device binding and a UTC assessment time. Providers must obtain observations from an authenticated integration and bind them to the same endpoint through a trusted enrollment mapping. Verifiers must validate the source's proof and its relationship to the reported source. Client-supplied health values, scores, bindings, and proof are not accepted by the access API. Freshness, timezone-aware observation time, binding, source identifier, and proof are checked before PASS/FAIL evidence is scored. UNKNOWN is never treated as a successful check; its reason code is restricted to a safe allow-list before serialization.

## Admin investigation output

The admin investigation response adds an optional nested `device_health_assessment` object to `context_signals`. It includes the posture version, classification, nullable verified score, completeness, verified-check count out of five, safe reason codes, and an allow-listed per-check state, validation status, observation time, and reason code. It deliberately excludes provider proof, source labels, and device bindings. Historical rows without the posture version retain their legacy device-health label and have no assessment details. The employee portal continues to show `Unknown · posture unverified` when no verified posture exists.

This is an additive admin-response/schema change and reuses the existing `raw_context` JSONB field. It does not add a database column or alter access-evaluation request/response bodies. Persisting the new normalized value `unknown` requires migration `20261013_13_device_health_unknown`; the migration updates only the accepted CHECK vocabulary and does not rewrite historical signals.

## Next integration step

Choose and provision a real endpoint-management or EDR service, define its authenticated enrollment/device identity mapping, and implement a server-only provider plus source-specific signature/attestation verifier. Validate its key rotation, replay protection, event freshness, device offboarding, and outage behavior before enabling it. Until then the five checks remain UNKNOWN and the policy engine receives zero posture points for missing evidence.
