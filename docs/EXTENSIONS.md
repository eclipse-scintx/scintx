# SCINTX Provider Adapter Extensions

Provider adapters live under `extensions/providers/<slug>/` and implement the `api.ProviderAdapter` interface defined in `api/adapter.go` (#70):

1. `Descriptor() api.AdapterDescriptor`: Declares the adapter's `slug`, `adapterVersion`, `supportedSchemaVersion` (`"1"`), `supportedInputs` (`types`, `ecosystems`, `digestAlgorithms`, `maxContentBytes`), and `capabilities` (`vulnerabilities`, `threats`, `licenses`, `health`, `integrity`, `dependencies`).
2. `CheckAvailability(ctx context.Context) api.AvailabilityStatus`: Verifies configuration, credentials, and upstream readiness (`ready`, `degraded`, `unconfigured`, `unreachable`) and returns machine-readable reason codes (`missing_credentials`, `invalid_configuration`, `rate_limited`, `upstream_unreachable`).
3. `Evaluate(ctx context.Context, req api.EvaluationRequest) (*api.EvaluationResult, error)`: Queries the upstream provider and returns a normalized `api.ProviderReport` (or a structured `*api.AdapterError` on timeout, rate-limit, auth, malformed response, or availability failure).

## Registering a New Adapter

1. Create a package under `extensions/providers/<slug>/`.
2. Call `api.RegisterAdapterFactory("<slug>", ...)` in `init()`.
3. Run `make generate` (`./scripts/generate.sh`) to update `extensions/providers/all/all.go`.
