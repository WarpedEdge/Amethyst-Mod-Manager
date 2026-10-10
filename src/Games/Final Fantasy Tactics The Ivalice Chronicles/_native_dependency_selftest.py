"""Static unchanged-archive native dependency checks; never load release code."""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from fftic_mod_state import contract_for
from fftic_packages import PackageClassification, inspect_package

_NGP_SHA256 = 'f385c712aebdc0af1a71fdabe4e6faf950169ebfd4a5e7cefe9aa86ec3e6d93f'
_FAITH_SHA256 = '7a9879d9f517e151d9a099c43d1999558316599bcb3ba2549aea824a7f08009a'


def extract_exact(archive, digest, expected_size, target):
    archive = Path(archive)
    assert archive.is_file() and archive.stat().st_size == expected_size
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest
    target.mkdir()
    subprocess.run(['7z', 'x', '-y', f'-o{target}', str(archive)],
                   check=True, capture_output=True, timeout=60)


def test_new_game_plus(archive):
    with tempfile.TemporaryDirectory(prefix='fftic-native-dependency-') as tmp:
        root = Path(tmp) / 'package'
        extract_exact(archive, _NGP_SHA256, 2474233, root)
        result = inspect_package(root)
        assert result.classification == PackageClassification.ENHANCED_MANAGED_CODE, result.diagnostics
        assert result.manifest.mod_id == 'fftivc.battles.ngplus'
        assert result.manifest.managed_native_declarations == (
            ('ModDll', 'fftivc.battles.ngplus.dll'),)
        assert len([p for p in root.rglob('*.layout')]) == 1070
        contract = contract_for(root)
        assert contract['entry_points'] == [['ModDll', 'fftivc.battles.ngplus.dll']]
        original_identity = contract['package_sha256']

        # The author package remains complete. Each changed/deleted native file
        # must make the package refuse instead of silently falling back to a RID.
        native = root / 'runtimes/win-x64/native/dstorage.dll'
        original = native.read_bytes()
        pe = struct.unpack_from('<I', original, 0x3c)[0]
        changed = bytearray(original)
        struct.pack_into('<H', changed, pe + 4, 0x14c)
        native.write_bytes(changed)
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        native.write_bytes(original)
        assert contract_for(root)['package_sha256'] == original_identity
        changed = bytearray(original)
        changed[-1] ^= 1
        native.write_bytes(changed)
        assert contract_for(root)['package_sha256'] != original_identity
        native.write_bytes(original)
        native.unlink()
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        native.write_bytes(original)

        unknown = root / 'unlisted.dll'
        shutil.copyfile(native, unknown)
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        unknown.unlink()

        manifest = root / 'ModConfig.json'
        manifest_original = manifest.read_bytes()
        config = json.loads(manifest.read_text())
        config['ModNativeDll64'] = 'runtimes/win-x64/native/dstorage.dll'
        manifest.write_text(json.dumps(config))
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        config['ModNativeDll64'] = ''
        config['ModDll'] = 'runtimes/win-x64/native/dstorage.dll'
        manifest.write_text(json.dumps(config))
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        manifest.write_bytes(manifest_original)
        assert inspect_package(root).classification == PackageClassification.ENHANCED_MANAGED_CODE

        deps_path = root / 'fftivc.battles.ngplus.deps.json'
        deps_original = deps_path.read_bytes()
        deps = json.loads(deps_original)
        target = next(iter(deps['targets'].values()))
        targets = target['Vortice.DirectStorage/3.6.2']['runtimeTargets']
        del targets['runtimes/win-x64/native/dstorage.dll']
        deps_path.write_text(json.dumps(deps))
        assert inspect_package(root).classification == PackageClassification.UNSUPPORTED_CODE
        deps_path.write_bytes(deps_original)
        assert contract_for(root)['package_sha256'] == original_identity
    print('PASS exact New Game++ native RID declaration and refusal boundaries')


def test_faith(archive):
    with tempfile.TemporaryDirectory(prefix='fftic-faith-native-') as tmp:
        root = Path(tmp) / 'package'
        extract_exact(archive, _FAITH_SHA256, 8294410, root)
        result = inspect_package(root)
        assert result.manifest.supported_app_ids == (
            'ffxvi.exe', 'ffxvi_demo.exe', 'fft_enhanced.exe', 'fft_classic.exe')
        assert result.classification == PackageClassification.UNSUPPORTED_CODE
        assert 'ImGui/Binaries' in result.diagnostics[0]
    print('PASS exact Faith archive retains separate ImGui native hold')


if __name__ == '__main__':
    base = Path('/var/tmp/amethyst-fftic-ecosystem-vy5komvh')
    ngp = os.environ.get('FFTIC_NEW_GAME_PLUS_ARCHIVE', base / 'fftivc.battles.ngplus1.0.0.7z')
    faith = os.environ.get('FFTIC_FAITH_FRAMEWORK_ARCHIVE', base / 'FaithFramework2.2.1.7z')
    test_new_game_plus(ngp)
    test_faith(faith)
