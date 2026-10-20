# NahaN Subscription Gateway v0.1.4

Ensures reinstalling an existing deployment activates replacement credentials,
even when the gateway image has not changed.

## Changes
- Explicit installation/reinstallation recreates only the managed gateway
  container, so changed enrollment files are loaded into the running process.
- Certificate-only renewal remains a synchronization/hot-reload operation and
  does not recreate the gateway.
- Add a regression test for credential reload during explicit installation.
- Retain validated asset version queries, heartbeat fallback, strict TLS and
  digest-pinned installation bundles from the previous releases.

## Upgrade
Use the existing protected enrollment file and the same bind/proxy settings.
Reinstallation may briefly interrupt subscription fetches from that gateway;
it does not restart the VPN core or change customer tokens/configurations.
