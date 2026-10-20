# NahaN Subscription Gateway v0.1.0

## Summary
Initial isolated Docker subscription delivery service for hosts enrolled in NahaN.

## Changes
- Deliver raw subscriptions, browser pages, presentation metadata and QR images.
- Preserve client negotiation and subscription metadata headers.
- Authenticate each domain deployment with a separately revocable credential.
- Verify HTTPS upstreams and fail over on eligible connection/service failures.
- Synchronize centrally issued certificates without exposing DNS credentials.
- Support a dedicated IP listener or explicit existing nginx-proxy integration.
- Provide a checksum-pinned installer and digest-pinned Docker Compose bundle.
- Bound request sizes, concurrency, resources, renewal retries and logs.

## Installation
Create a deployment in NahaN, obtain its protected enrollment file, and run the
versioned installer. Existing listeners are never stopped automatically. Central
subscription delivery and private certificate issuance must be configured first.
