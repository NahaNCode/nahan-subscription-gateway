# NahaN Subscription Gateway v0.1.1

## Summary
Managed, isolated subscription delivery for NahaN-enrolled Docker hosts.

## Changes
- Serve raw subscriptions, browser pages, presentation metadata and QR images.
- Preserve client content negotiation and subscription usage/update headers.
- Authenticate per-domain deployments with independently revocable credentials.
- Verify upstream TLS and retry eligible network and service failures.
- Synchronize centrally issued leaf certificates without DNS API credentials.
- Support dedicated IPs and existing nginx-proxy integration without stopping listeners.
- Disable bearer-URL access/error logging for managed proxy virtual hosts.
- Validate proxy configuration before graceful reload and restore files on failure.
- Provide bounded Docker resources/logs, local health checks and a pinned installer bundle.

## Upgrade Notes
Central private subscription delivery and certificate issuance must be configured
first. Existing unrelated proxy virtual hosts are never overwritten. Each local
enrollment file contains a private deployment credential and must remain protected.
