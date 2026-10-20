# Verified CDN Origin TLS Aliases

- Accept exact, source-bound CDN SNI names only while authenticated alias authorization is fresh.
- Require the loaded origin certificate to cover the requested SNI and remain valid.
- Support multi-name origin bundles shared by the direct listener and existing NGINX deployments.
- Preserve source identity, unknown-host rejection, upstream TLS verification and route isolation.
- Add verified TLS handshake and alias expiry/name mismatch regression tests.

Issue and deploy an appropriate origin certificate before enabling alias SNI.
No VPN core or tunnel changes.
