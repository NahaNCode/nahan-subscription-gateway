# Security

Subscription URLs are bearer credentials. Do not include them, enrollment
credentials, certificate private keys or response bodies in issue reports.

Report vulnerabilities privately to the NahaN platform owner. The gateway
requires a protected NahaN deployment identity and verified TLS. Public code
does not confer access to the platform or to another domain's certificate.

The local installer runs as root to manage Docker and certificate integration.
Review its versioned source and release pins before execution. The serving
container runs without root, capabilities, a Docker socket or DNS credentials.
