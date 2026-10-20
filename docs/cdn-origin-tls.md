# CDN Origin TLS Names

An HTTP Host alias alone does not authorize TLS SNI. The gateway accepts alias
SNI only while its authenticated source-bound alias authorization is fresh and
the current origin certificate actually covers that exact name. An unknown,
expired, removed, or uncovered name is rejected before HTTP. TLS verification
on the CDN must remain enabled.

For deployments behind an existing NGINX proxy, the managed origin bundle can
contain both the source hostname and explicitly approved CDN alias as DNS SANs.
The existing installer exports the complete chain and private key, validates
NGINX configuration, and gracefully reloads it with rollback on export failure.
The same source bundle works on the direct Go TLS listener. Do not replace the
source identity or route upstream traffic under the untrusted viewer Host.

The private issuer may obtain this SAN group with DNS-01. Delegate each external
alias's `_acme-challenge` name using a DNS-only CNAME to a unique name in the
issuer-controlled DNS zone. The main CDN record stays proxied. No CDN API key is
needed on either gateway, and neither port 80 nor HTTP-01 is required.

Deployment order: configure the exact certificate names, verify delegation on
authoritative DNS, test issuance against ACME staging in isolated storage, then
issue the trusted production bundle. Deploy source-bound SAN validation in the
backend before publishing the new bundle. Upgrade gateways before testing alias
SNI. Confirm both source and alias with verified TLS against every origin, then
run real CDN subscription, HTML and asset tests. Do not promote the CDN hostname
based solely on a successful panel probe.

Certificate groups are operator-managed. Before deleting an alias registration,
remove it from the group and issue a reduced source bundle. Backend certificate
delivery rejects SANs that no longer belong to that source; retained source TLS
continues using its last valid bundle, but renewal must not be left blocked.
