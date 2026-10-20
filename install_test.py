import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install.py'))
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class InstallerTest(unittest.TestCase):
 def test_proxy_aliases_are_bounded_and_reject_nginx_injection(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'state').mkdir();(root/'certs').mkdir();(root/'vhosts').mkdir()
   (root/'state/server.pem').write_text('-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n')
   settings={'hostname':'origin.example.com','proxyCertDir':str(root/'certs'),'proxyVhostDir':str(root/'vhosts'),'proxyContainer':'proxy'}
   with mock.patch.object(installer,'proxy_preflight'),mock.patch.object(installer,'run',return_value='certificate'):
    for aliases in [['nnn.fg-t.ir; access_log /tmp/log'],['*.fg-t.ir'],['a.example.com']*51]:
     (root/'state/host-aliases.json').write_text(json.dumps(aliases))
     with self.assertRaises(ValueError):installer.export_proxy(root,settings)
    (root/'state/host-aliases.json').write_text('["nnn.fg-t.ir"]')
    installer.export_proxy(root,settings)
    config=root/'vhosts/origin.example.com'
    self.assertIn('server_name nnn.fg-t.ir;',config.read_text())
    installer.export_proxy(root,settings)
    (root/'state/host-aliases.json').write_text('[]')
    installer.export_proxy(root,settings)
    self.assertNotIn('server_name',config.read_text())
 def test_explicit_install_recreates_gateway_to_reload_credentials(self):
  root=Path('/opt/nahan-edge')
  with mock.patch.object(installer,'compose') as compose:
   installer.start_gateway(root)
  compose.assert_called_once_with(root,'up','-d','--force-recreate','--wait','--wait-timeout','30')
 def test_bundle_verifies_all_file_hashes(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);files={}
   for name in installer.FILES:
    data=b'services: {}\n';(root/name).write_bytes(data);files[name]=hashlib.sha256(data).hexdigest()
   manifest=json.dumps({'schemaVersion':1,'image':'ghcr.io/example/gateway@sha256:'+'a'*64,'files':files}).encode()
   (root/'manifest.json').write_bytes(manifest)
   args=types.SimpleNamespace(bundle_dir=directory,manifest_sha256=hashlib.sha256(manifest).hexdigest())
   self.assertEqual(len(installer.bundle(args)[1]),2)
   (root/installer.FILES[0]).write_bytes(b'changed')
   with self.assertRaises(ValueError):installer.bundle(args)
 def test_mutable_image_and_manifest_mismatch_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'manifest.json').write_text('{"schemaVersion":1,"image":"example:latest"}')
   for pin in [None,'a'*64]:
    with self.assertRaises(ValueError):installer.bundle(types.SimpleNamespace(bundle_dir=directory,manifest_sha256=pin))

if __name__=='__main__':unittest.main()
