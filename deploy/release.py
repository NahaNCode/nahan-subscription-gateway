"""Create a pinned public installation bundle; no operator inputs or secrets."""
import hashlib
import json
from pathlib import Path
import re
import sys

image=sys.argv[1]
if not re.fullmatch(r'ghcr\.io/nahancode/nahan-subscription-gateway@sha256:[a-f0-9]{64}',image):
 raise SystemExit('Immutable gateway image required')
root=Path(__file__).resolve().parent.parent
out=root/'release';out.mkdir(exist_ok=True)
files={}
for name in ['compose.yaml','compose.proxy.yaml']:
 data=(root/'deploy'/name).read_bytes();(out/name).write_bytes(data);files[name]=hashlib.sha256(data).hexdigest()
installer=(root/'install.py').read_bytes();(out/'install.py').write_bytes(installer)
manifest=json.dumps({'schemaVersion':1,'version':'v0.1.0','image':image,'files':files},sort_keys=True,separators=(',',':')).encode()
(out/'manifest.json').write_bytes(manifest)
script=(root/'install.sh').read_text().replace('__MANIFEST_SHA256__',hashlib.sha256(manifest).hexdigest()).replace('__INSTALLER_SHA256__',hashlib.sha256(installer).hexdigest())
(out/'install.sh').write_text(script)
checks=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.is_file() and p.name!='SHA256SUMS')
(out/'SHA256SUMS').write_text(checks)
