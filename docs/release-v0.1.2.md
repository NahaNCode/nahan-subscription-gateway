# NahaN Subscription Gateway v0.1.2

Improves deployment receipt reliability when one approved backend is unavailable.

## Changes
- Retry idempotent heartbeat receipts through the next configured upstream on
  network errors and HTTP 502, 503 or 504, within the existing time budget.
- Preserve immediate rejection of revoked credentials and authentication errors.
- Add regression coverage for unavailable upstreams, network failure and revocation.
- Publish updated, checksum-verified installers and digest-pinned Docker images.

## Upgrade
Run the versioned installer with the existing protected enrollment file and the
same installation mode. Subscription tokens, domain certificates and customer
configuration do not change. Backend access remains mandatory for subscription
delivery; multiple DNS addresses are not a guarantee of client-side failover.
