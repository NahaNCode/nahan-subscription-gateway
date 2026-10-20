# NahaN Subscription Gateway

An isolated subscription delivery edge for hosts enrolled in NahaN. It does
not run a VPN core, contain a customer database, or support unrelated panels.

## Responsibilities

- Deliver subscription text, browser pages, presentation metadata and QR images.
- Preserve client content negotiation and subscription usage/update headers.
- Authenticate with a revocable credential scoped to one domain deployment.
- Connect to approved HTTPS upstreams with full certificate verification.
- Download and hot-reload the domain certificate from NahaN's private issuer.
- Reject unknown hosts, arbitrary proxy paths, redirects and oversized responses.
- Bound concurrency, timeouts, Docker resources and logs. Never log bearer URLs.

DNS-provider credentials and ACME account keys stay on the private central
issuer. Only the assigned domain's leaf certificate/key reaches the gateway.
No production credentials, customer configuration or private keys belong here.

## Installation

Create a domain deployment in the NahaN subscription settings and download its
one-time enrollment JSON. Transfer it privately and run `chmod 600` on it.
The versioned release installer uses a digest-pinned image and checks the
release manifest and Compose files before starting anything.

The installer requires Docker Compose, Python 3 and OpenSSL. It does not
silently install packages or stop an existing listener. Select either a specific
local bind IP, or the explicit existing nginx-proxy integration mode. In proxy
mode, certificate export and graceful reload run on the host, never through a
Docker socket inside the gateway.

For a reviewed local bundle:

```sh
sudo python3 install.py --bundle-dir ./release --install-dir /opt/nahan-edge \
  --enrollment-file /root/nahan-gateway-enrollment.json \
  --bind-ip YOUR_LOCAL_IP --install-timer
```

Existing proxy mode additionally requires `--behind-proxy --proxy-container
nginx-proxy --proxy-cert-dir /absolute/certificate/directory
--proxy-owner-consent` instead of `--bind-ip`. Renewals synchronize the leaf
material and reload only the proxy after `nginx -t` succeeds.

The edge relays central entitlement decisions. It is not an offline database
replica: losing all configured backend routes prevents new subscription fetches.
Multiple DNS addresses do not guarantee immediate failover in every client.

## Development

```sh
go test -race ./...
go vet ./...
python3 -m py_compile install.py
docker build -t nahan-subscription-gateway:dev .
```

Only operator-owned configuration may choose upstream destinations and trust
roots. External HTTP headers never choose either. Keep enrollment files, Docker
state, exported keys and local backups out of source control.
