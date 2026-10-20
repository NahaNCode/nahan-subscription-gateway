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
