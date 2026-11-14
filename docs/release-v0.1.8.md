# Emergency Traffic Claims

Supports GET and bounded POST on the subscription emergency endpoint. Claims
require a same-origin HTTPS browser request, an exact UUID request payload,
and a maximum 1 KiB body. Other subscription paths remain read-only. Private
browser credentials are never forwarded; existing edge identity and verified
upstream TLS remain required. Request UUIDs survive upstream failover so the
control plane can safely replay a claim without granting twice.
