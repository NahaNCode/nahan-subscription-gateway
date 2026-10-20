# CDN Connection Compatibility

- Close HTTP/1.1 origin connections for registered CDN Host aliases to avoid stale CDN pool failures.
- Apply the equivalent bounded keepalive policy to the gateway-owned NGINX virtual host.
- Preserve verified TLS, source-bound Host admission and private-route isolation.

No VPN core or tunnel changes.
