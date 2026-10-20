# NahaN Subscription Gateway v0.1.3

Fixes delivery of versioned subscription page assets. This release is recommended
for managed deployments, including existing reverse-proxy installations.

## Changes
- Accept a single validated `v` cache-version parameter on subscription assets.
- Keep duplicate parameters, unknown keys, URLs and invalid version values blocked.
- Add regression tests for styled asset delivery and query isolation.
- Include v0.1.2 heartbeat failover across approved upstreams, with authentication
  refusal remaining terminal and all requests bounded by the existing timeout.
- Publish checksum-verified installation bundles and immutable Docker images.

## Upgrade
Rerun the versioned installer using the existing enrollment file and installation
mode. Customer tokens and domain certificates remain unchanged. The gateway
still requires backend connectivity and does not replicate customer databases.
