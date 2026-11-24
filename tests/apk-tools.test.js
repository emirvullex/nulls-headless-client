const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const Platform = require('../utils/Platform');

test('APK extractor discovers latest SDK aapt2 when it is absent from PATH', (t) => {
  const python = Platform.pythonCommand();
  if (!python) return t.skip('Python is not installed');
  const modulePath = path.resolve(__dirname, '../tools/extract_update_apk.py');
  const script = [
    'import importlib.util, os, pathlib, sys, tempfile',
    'spec=importlib.util.spec_from_file_location("extract_update_apk", sys.argv[1])',
    'module=importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(module)',
    'module.shutil.which=lambda name: None',
    'with tempfile.TemporaryDirectory() as tmp:',
    '  root=pathlib.Path(tmp)',
    '  module.Path.home=classmethod(lambda cls: root)',
    '  os.environ["ANDROID_HOME"]=tmp',
    '  os.environ["ANDROID_SDK_ROOT"]=tmp',
    '  os.environ.pop("AAPT2_PATH", None)',
    '  os.environ["LOCALAPPDATA"]=tmp',
    '  for v in ("9.0.0","35.0.0"):',
    '    dest=root/"build-tools"/v/("aapt2.exe" if os.name=="nt" else "aapt2")',
    '    dest.parent.mkdir(parents=True, exist_ok=True)',
    '    dest.write_bytes(b"fixture")',
    '  found=module.find_aapt2()',
    '  assert pathlib.Path(found).parent.name=="35.0.0", found',
    'print("ok")',
  ].join('\n');
  const result = spawnSync(python, ['-c', script, modulePath], { encoding: 'utf8', timeout: 8000 });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /ok/);
});
