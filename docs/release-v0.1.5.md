# Registered CDN Host Aliases

- Accept owner-registered CDN Host headers without a paid CDN Host override.
- Synchronize source-bound aliases over the authenticated control connection.
- Reject unknown hosts, invalid alias data and authorizations older than five minutes.
- Refresh managed NGINX virtual-host aliases during certificate synchronization.
- Preserve origin TLS SNI and certificate verification; viewer TLS remains CDN-managed.

No changes to VPN cores, customer endpoints or tunnels.
