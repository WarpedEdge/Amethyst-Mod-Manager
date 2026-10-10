"""Generic static/lifecycle/production fixtures. No release binary is executed."""
import _selftest  # Set all shared XDG/profile lookups to disposable roots first.
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from _managed_fixture import managed_bytes
from _c3c_selftest import Fixture, _owned_state, _manifest
from fftic_packages import inspect_package, PackageClassification, is_managed_dll
from fftic_mod_state import (MAX_MANAGED_STATE_FILES, ModWorkingPolicy,
                             new_store, stores_for, working_baseline)
from fftic_color_state import ColorStateError
from fftic_generation import verify_private_generation, content_manifest, manifest_digest
from fftic_generation import GenerationError, validate_user_dependencies
from fftic_reloaded_config import (UserMod, ValidatedSteamPath,
                                  generate_reloaded_configuration, MANAGED_ORDER)
from fftic_orchestration import OperationKind
from fftic_managed_executor import OperationState
from fftic_receipts import read_receipt, validate_receipt, ReceiptCorruptError
from fftic_readiness import ReadinessAspect

GENERIC_JOBS_SHA256 = '815f944766db13d9671489784a3dd7ebeb6958b9028de2f253d6058c23730514'
GENERIC_JOBS_ID = 'ffttic.jobs.genericjobs'
NEW_GAME_PLUS_SHA256 = 'f385c712aebdc0af1a71fdabe4e6faf950169ebfd4a5e7cefe9aa86ec3e6d93f'


def write(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def package(root, mod_id, version='1.0', seed=b'author-default', apps=None):
    root.mkdir(parents=True)
    data = dict(_manifest(mod_id, apps or ['fft_enhanced.exe']), ModDll='Entry.dll', ModVersion=version)
    (root / 'ModConfig.json').write_text(json.dumps(data))
    write(root, 'Entry.dll', managed_bytes(version.encode()))
    write(root, 'Support.dll', managed_bytes(b'support'))
    write(root, 'Entry.deps.json', b'{}')
    write(root, 'Data/default.json', seed)
    return root


def rejected(fn):
    try:
        fn()
    except (ColorStateError, RuntimeError, ValueError):
        return
    raise AssertionError('unsafe fixture accepted')


def active(f):
    receipt = read_receipt(f.inputs.receipts_root)
    root = Path(receipt.data['active_generation_identity']['root'])
    return receipt, root, json.loads((root / 'amethyst-generation.json').read_text())


def test_application_intersection():
    with tempfile.TemporaryDirectory(prefix='fftic-app-intersection-') as tmp:
        root = Path(tmp)
        package_root = package(root / 'mixed', 'author.mixed',
                               apps=['ffxvi.exe', 'ffxvi_demo.exe',
                                     'fft_enhanced.exe', 'fft_classic.exe'])
        manifest_path = package_root / 'ModConfig.json'
        original = manifest_path.read_bytes()
        inspected = inspect_package(package_root)
        assert inspected.classification == PackageClassification.DUAL_MODE_MANAGED_CODE
        assert inspected.manifest.supported_app_ids == (
            'ffxvi.exe', 'ffxvi_demo.exe', 'fft_enhanced.exe', 'fft_classic.exe')
        (root / 'profile').mkdir()
        policy = new_store(root / 'profile', package_root).policy
        contract = policy.contract
        assert contract['schema'] == 2
        assert contract['applications'] == list(inspected.manifest.supported_app_ids)
        assert contract['selected_applications'] == ['fft_enhanced.exe', 'fft_classic.exe']
        rejected(lambda: ModWorkingPolicy(dict(contract,
            selected_applications=['fft_enhanced.exe']),
            ({policy.mod + path: value for path, value in policy.package_files.items()},
             {policy.mod + path for path in policy.package_dirs})))
        assert manifest_path.read_bytes() == original
        mod = UserMod('author.mixed', package_root, inspected.classification, True, 0)
        config = generate_reloaded_configuration(
            private_generation_root=root.resolve(),
            windows_game_path=ValidatedSteamPath.from_resolver(
                r'S:\steamapps\common\FFTIC'),
            managed_package_locations={name: root / name for name in MANAGED_ORDER},
            user_mods=(mod,))
        assert set(config.files) == {'portable.txt',
            'Apps/fft_classic.exe/AppConfig.json',
            'Apps/fft_enhanced.exe/AppConfig.json'}
        for app in ('fft_classic.exe', 'fft_enhanced.exe'):
            record = json.loads(config.files[f'Apps/{app}/AppConfig.json'])
            assert record['EnabledMods'][-1] == 'author.mixed'
            assert record['AppId'] == app
        irrelevant = package(root / 'irrelevant', 'author.other', apps=['ffxvi.exe'])
        assert inspect_package(irrelevant).classification == PackageClassification.UNSUPPORTED_APPLICATION
        rejected(lambda: new_store(root / 'profile', irrelevant))
        # A mixed app dependency must still be enabled in each selected FFTIC mode.
        dependency = package(root / 'dependency', 'author.dependency', apps=['fft_enhanced.exe'])
        data = json.loads(manifest_path.read_text())
        data['ModDependencies'] = ['author.dependency']
        manifest_path.write_text(json.dumps(data))
        target = UserMod('author.dependency', dependency,
                         inspect_package(dependency).classification, True, 1)
        try:
            validate_user_dependencies((mod, target))
        except GenerationError as exc:
            assert 'author.dependency' in str(exc) and 'classic' in str(exc)
        else:
            raise AssertionError('Classic-only missing dependency was accepted')
        data['ModDependencies'] = ['Reloaded.Memory.SigScan.ReloadedII',
                                   'reloaded.sharedlib.hooks']
        manifest_path.write_text(json.dumps(data))
        validate_user_dependencies((mod,))
        # The unchanged author manifest is static evidence; its native ImGui
        # dependencies still prevent complete package acceptance.
        faith_root = os.environ.get('FFTIC_FAITH_FRAMEWORK_ROOT')
        if faith_root:
            faith = Path(faith_root)
            actual = inspect_package(faith)
            assert actual.manifest.supported_app_ids == (
                'ffxvi.exe', 'ffxvi_demo.exe', 'fft_enhanced.exe', 'fft_classic.exe')
            assert actual.classification == PackageClassification.UNSUPPORTED_CODE
            assert 'ImGui/Binaries' in actual.diagnostics[0]
    print('PASS FFTIC application intersection and optional unchanged Faith boundary')


class ModFixture(Fixture):
    def plan(self, kind):
        plan = super().plan(kind)
        return replace(plan, binding=replace(plan.binding, profile_dir=str(self.inputs.profile_dir),
                                            staging_root=str(self.inputs.staging_root)))


def passed(f, kind):
    result = f.run(kind)
    assert result.state == OperationState.SUCCEEDED, result
    return active(f) if kind != OperationKind.REMOVE else None


def test_boundary():
    with tempfile.TemporaryDirectory(prefix='fftic-contract-boundary-') as tmp:
        root = Path(tmp)
        pristine = package(root / 'package', 'another.settings')
        assert inspect_package(pristine).is_user_content
        assert is_managed_dll(pristine / 'Entry.dll')
        original = (pristine / 'Entry.dll').read_bytes()
        for offset, value in ((528, 0), (528, 0x11), (0x84, 0xaa64), (592, 0)):
            changed = bytearray(original)
            struct.pack_into('<H' if offset == 0x84 else '<I', changed, offset, value)
            (pristine / 'Entry.dll').write_bytes(changed)
            assert inspect_package(pristine).classification == PackageClassification.UNSUPPORTED_CODE
        (pristine / 'Entry.dll').write_bytes(original)
        for member, data in [('unknown.dll', b'MZnative'), ('launch.exe', b'MZ'),
                             ('lib.so', b'\x7fELF'), ('launch.ps1', b'echo'), ('renamed.dat', b'MZnative')]:
            write(pristine, member, data)
            assert inspect_package(pristine).classification == PackageClassification.UNSUPPORTED_CODE
            (pristine / member).unlink()
        for member in ('../outside', 'C:/bad', 'folder\\bad', 'Data/default.JSON', 'NUL.txt', 'trailing.'):
            if member == '../outside':
                config = json.loads((pristine / 'ModConfig.json').read_text())
                (pristine / 'ModConfig.json').write_text(json.dumps(dict(config, ModDll=member)))
                assert inspect_package(pristine).classification == PackageClassification.MALFORMED
                (pristine / 'ModConfig.json').write_text(json.dumps(config))
            else:
                write(pristine, member, b'bad')
                assert inspect_package(pristine).classification == PackageClassification.MALFORMED
                (pristine / member).unlink()
        if (pristine / 'C:').exists():
            shutil.rmtree(pristine / 'C:')
        (pristine / 'link').symlink_to(root)
        assert inspect_package(pristine).classification == PackageClassification.MALFORMED
        (pristine / 'link').unlink()
        os.link(pristine / 'Entry.dll', pristine / 'hardlink.dll')
        assert inspect_package(pristine).classification == PackageClassification.MALFORMED
        (pristine / 'hardlink.dll').unlink()
        os.mkfifo(pristine / 'fifo')
        assert inspect_package(pristine).classification == PackageClassification.MALFORMED
        (pristine / 'fifo').unlink()
        profile = root / 'profile'; profile.mkdir()
        store = new_store(profile, pristine)
        work = root / 'work'; shutil.copytree(pristine, work / store.policy.mod.rstrip('/'))
        baseline = store.policy._working_scan(work)
        for member, data in [('User/Mods/another.settings/unknown.dll', managed_bytes()),
                             ('Mods/another.settings/Entry.deps.json', b'changed'),
                             ('Mods/another.settings/Entry.dll', managed_bytes(b'changed')),
                             ('User/Mods/another.settings/renamed.dat', b'\x7fELFpayload')]:
            target = work / member
            old = target.read_bytes() if target.exists() else None
            write(work, member, data)
            rejected(lambda: store.policy.inspect(work, baseline))
            if old is None:
                target.unlink()
            else:
                target.write_bytes(old)
        # Runtime paths use the same private path/type boundary as packages.
        for kind in ('link', 'hardlink', 'fifo', 'collision', 'oversize'):
            target = work / (store.policy.user + 'bad.bin')
            target.parent.mkdir(parents=True, exist_ok=True)
            if kind == 'link':
                target.symlink_to(pristine / 'Data/default.json')
            elif kind == 'hardlink':
                os.link(pristine / 'Data/default.json', target)
            elif kind == 'fifo':
                os.mkfifo(target)
            elif kind == 'collision':
                target.write_bytes(b'x')
                target.with_name('BAD.bin').write_bytes(b'y')
            else:
                with target.open('wb') as stream:
                    stream.truncate(65 * 1024 * 1024)
            rejected(lambda: store.policy.inspect(work, baseline))
            target.unlink()
            if kind == 'collision':
                target.with_name('BAD.bin').unlink()
        write(work, store.policy.user + 'state.bin', b'opaque')
        rejected(lambda: store.capture(work, baseline, expected_head=None, process_running=lambda: True))
        revision = store.capture(work, baseline, expected_head=None, process_running=lambda: False)
        rejected(lambda: store.publish(revision, expected_head=None, transaction='test', generation='test',
                                       process_running=lambda: False, failure_injector=lambda _: (_ for _ in ()).throw(RuntimeError('failure'))))
        assert store.head() is None
        head = store.publish(revision, expected_head=None, transaction='test', generation='test', process_running=lambda: False)
        rejected(lambda: store.capture(work, baseline, expected_head=None, process_running=lambda: False))
        export = root / 'export'; store.export(revision, export)
        assert (export / 'payload' / (store.policy.user + 'state.bin')).read_bytes() == b'opaque'
        rejected(lambda: store.export(revision, export))
        store.rollback_publication(expected_head=head, previous_head=None, process_running=lambda: False)
        assert store.head() is None and store.read(revision)
        class Interrupted(BaseException):
            pass
        def interrupt(point):
            if point == 'head':
                raise Interrupted()
        try:
            store.publish(revision, expected_head=None, transaction='interrupted', generation='test',
                          process_running=lambda: False, failure_injector=interrupt)
        except Interrupted:
            pass
        else:
            raise AssertionError('interruption did not run')
        assert (store.root / 'intent.json').is_file()
        rejected(lambda: store.capture(work, baseline, expected_head=store.head(), process_running=lambda: False))
        store.rollback_interrupted(process_running=lambda: False)
        assert store.head() is None and store.read(revision)
        print('PASS static payload boundary, unsafe paths/types, stopped capture, CAS, publication rollback and export')


def test_production():
    f = ModFixture('generic-user-mods')
    try:
        f.recompose(process_running=lambda: False)
        first = package(f.staging / 'First', 'author.first')
        # Shared installer consumes an unchanged synthetic author ZIP. It has a
        # different ID, version, inventory and DLL identity from the Color ZIP.
        source = package(f.root / 'second-source', 'different.second', apps=['fft_classic.exe', 'fft_enhanced.exe'])
        archive = f.root / 'second.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            for path in source.rglob('*'):
                if path.is_file():
                    output.write(path, 'author-folder/' + path.relative_to(source).as_posix())
        original_archive = archive.read_bytes()
        from Utils.mods.install import prepare_archive, finish_install
        from final_fantasy_tactics import FinalFantasyTacticsTheIvaliceChronicles
        with patch('Utils.mods.copy.resolve_target_staging', return_value=f.staging), \
             patch('Utils.mods.install._update_indexes'), \
             patch('Utils.mods.install._check_nexus_flags_after_install'):
            prepared = prepare_archive(str(archive), FinalFantasyTacticsTheIvaliceChronicles(), f.profile, log_fn=lambda _: None)
            assert prepared is not None
            prepared.mod_name = 'Second'
            assert finish_install(prepared, None, log_fn=lambda _: None) == 'Second'
        second = f.staging / 'Second'
        assert archive.read_bytes() == original_archive
        pristine = {p.name: manifest_digest(content_manifest(p)) for p in (first, second)}
        (f.profile / 'modlist.txt').write_text('+High\n+First\n-Second\n')
        receipt, root, manifest = passed(f, OperationKind.SETUP)
        assert manifest['schema_version'] == 3
        assert len(receipt.data['mod_states']) == 2
        stores = stores_for(manifest)
        old_store = stores['author.first']
        assert old_store.policy.contract['entry_points'] == [['ModDll', 'Entry.dll']]
        assert old_store.policy.contract['dependencies'] == ['fftivc.utility.modloader']
        p1, p2 = old_store.policy, stores['different.second'].policy
        write(root, p1.user + 'settings.json', b'{"theme":"one"}')
        write(root, p1.mod + 'Data/default.json', b'user-change')
        write(root, p1.mod + 'logs/session.txt', b'log')
        (root / (p2.mod + 'Data/default.json')).unlink()
        write(root, p2.user + 'settings.bin', b'other-state')
        assert f.composition.mod_state_pending()
        receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)
        assert f.composition.mod_state_pending() is None
        assert not (root / (p2.mod + 'Data/default.json')).exists()
        for point in ('mod-state:head', 'mod-state:receipt'):
            write(root, p2.user + 'settings.bin', point.encode())
            before = _owned_state(f)
            heads = {k: s.head() for k, s in stores_for(manifest).items()}
            def fail(name, _kind):
                if name == point:
                    raise RuntimeError('injected generic state failure')
            f.recompose(failure_injector=fail)
            rejected(lambda: f.run(OperationKind.SAVE_MOD_STATE))
            assert _owned_state(f) == before
            assert {k: s.head() for k, s in stores_for(manifest).items()} == heads
            f.recompose(failure_injector=None)
            receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)
        print('PASS two distinct managed identities, disabled state, production save and multiple-store rollback')
        # Another profile with identical packages gets independent stores/generation.
        other = f.profile.parent / 'other'; other.mkdir()
        (other / 'modlist.txt').write_text((f.profile / 'modlist.txt').read_text())
        f.recompose(profile_dir=other)
        _, other_root, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert other_root != root and not (other_root / (p1.user + 'settings.json')).exists()
        f.recompose(profile_dir=f.profile)
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        assert (root / (p1.user + 'settings.json')).read_bytes() == b'{"theme":"one"}'
        assert not (root / (p2.mod + 'Data/default.json')).exists()
        # Same seed defaults, changed assembly/manifest version: data transfers,
        # old code/store/revisions are preserved; new code is copied pristine.
        old_root = root
        old_code = (root / (p1.mod + 'Entry.dll')).read_bytes()
        old_revision = stores_for(manifest)['author.first'].head()['revision']
        shutil.rmtree(first); package(first, 'author.first', '2.0')
        before_transition = _owned_state(f)
        before_heads = {k: s.head() for k, s in stores_for(manifest).items()}
        def fail_activation(name, _kind):
            if name == 'activation':
                raise RuntimeError('injected version activation failure')
        f.recompose(failure_injector=fail_activation)
        rejected(lambda: f.run(OperationKind.SYNCHRONIZE))
        assert _owned_state(f) == before_transition
        assert {k: s.head() for k, s in stores_for(manifest).items()} == before_heads
        f.recompose(failure_injector=None)
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        updated = stores_for(manifest)['author.first']
        assert updated.root != old_store.root
        assert updated.policy.contract['version'] == '2.0'
        assert (root / (p1.mod + 'Entry.dll')).read_bytes() == managed_bytes(b'2.0')
        assert any(p.read_bytes() == old_code for p in f.inputs.quarantine_root.rglob('Entry.dll'))
        assert (root / (p1.mod + 'Data/default.json')).read_bytes() == b'user-change'
        assert (root / (p1.user + 'settings.json')).read_bytes() == b'{"theme":"one"}'
        assert old_store.read(old_revision)
        print('PASS independent profiles and version transfer with old code/revisions preserved')
        # Concurrent author and user changes refuse replacement. Export contains
        # outgoing state and receipt/activation/head remains exact.
        before = _owned_state(f)
        shutil.rmtree(first); package(first, 'author.first', '3.0', seed=b'new-author-default')
        rejected(lambda: f.run(OperationKind.SYNCHRONIZE))
        assert _owned_state(f) == before
        assert (root / (p1.mod + 'Data/default.json')).read_bytes() == b'user-change'
        shutil.rmtree(first); package(first, 'author.first', '1.0')
        rejected(lambda: f.run(OperationKind.SYNCHRONIZE))
        assert _owned_state(f) == before
        shutil.rmtree(first); package(first, 'AUTHOR.FIRST', '4.0')
        rejected(lambda: f.run(OperationKind.SYNCHRONIZE))
        assert _owned_state(f) == before
        shutil.rmtree(first); package(first, 'author.first', '4.0')
        config = json.loads((first / 'ModConfig.json').read_text())
        (first / 'ModConfig.json').write_text(json.dumps(dict(config, ModDll='')))
        (first / 'Entry.dll').unlink(); (first / 'Support.dll').unlink()
        write(first, 'FFTIVC/data/combined/content.nxd', b'content-only class transition')
        rejected(lambda: f.run(OperationKind.SYNCHRONIZE))
        assert _owned_state(f) == before
        exports = list(f.inputs.quarantine_root.glob('mod-user-state-*'))
        assert exports and all((p / 'revision.json').is_file() for p in exports)
        # Restore only the synthetic staged package to the last successful version.
        shutil.rmtree(first); package(first, 'author.first', '2.0')
        bad = dict(receipt.data, mod_states=[dict(receipt.data['mod_states'][0], package_sha256='0' * 64)])
        rejected(lambda: validate_receipt(bad))
        verify_private_generation(root)
        generation_hash = receipt.data['active_generation_identity']['manifest_sha256']
        _, ready = f.composition._readiness()
        assert ready.generation == ReadinessAspect.READY, ready.issues
        assert generation_hash == verify_private_generation(root)
        print('PASS version conflict preservation/export, receipt identity and readiness')
        write(root, p1.user + 'final.bin', b'final')
        passed(f, OperationKind.REMOVE)
        exports = list(f.inputs.quarantine_root.glob('mod-user-state-*'))
        assert any((e / 'payload' / (p1.user + 'final.bin')).is_file() for e in exports)
        assert manifest_digest(content_manifest(second)) == pristine['Second']
        assert old_store.read(old_revision)
        assert archive.read_bytes() == original_archive
        print('PASS stopped removal exports every mod and preserves pristine sources and old revisions')
    finally:
        shutil.rmtree(f.root)


def test_real_generic_jobs(archive):
    """Optional exact author archive; extraction and lifecycle stay in a disposable fixture."""
    archive = Path(archive).resolve(strict=True)
    assert archive.stat().st_size == 869192
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == GENERIC_JOBS_SHA256
    f = ModFixture('real-generic-jobs')
    try:
        f.recompose(process_running=lambda: False)
        source = f.root / 'author-package'
        source.mkdir()
        subprocess.run(['7z', 'x', '-y', f'-o{source}', str(archive)],
                       check=True, capture_output=True, timeout=30)
        assert (source / 'ModConfig.json').is_file()
        author_files = {p.relative_to(source).as_posix(): (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
                        for p in source.rglob('*') if p.is_file()}
        assert len(author_files) == 55
        inspected = inspect_package(source)
        assert inspected.classification == PackageClassification.ENHANCED_MANAGED_CODE
        assert inspected.manifest.mod_id == GENERIC_JOBS_ID
        assert inspected.manifest.dependencies == (
            'fftivc.utility.modloader', 'Reloaded.Memory.SigScan.ReloadedII',
            'reloaded.sharedlib.hooks')
        assert inspected.manifest.supported_app_ids == ('fft_enhanced.exe',)
        assert not (source / 'x86/GenericJobs.dll').exists()
        assert not (source / 'x64/GenericJobs.dll').exists()
        assert (source / 'GenericJobs.dll').is_file()

        from Utils.mods.install import prepare_archive, finish_install
        from final_fantasy_tactics import FinalFantasyTacticsTheIvaliceChronicles
        with patch('Utils.mods.copy.resolve_target_staging', return_value=f.staging), \
             patch('Utils.mods.install._update_indexes'), \
             patch('Utils.mods.install._check_nexus_flags_after_install'):
            prepared = prepare_archive(str(archive), FinalFantasyTacticsTheIvaliceChronicles(),
                                       f.profile, preferred_name='Generic Jobs', log_fn=lambda _: None)
            assert prepared is not None
            assert finish_install(prepared, None, log_fn=lambda _: None) == 'Generic Jobs'
        staged = f.staging / 'Generic Jobs'
        staged_identity = manifest_digest(content_manifest(staged))
        for path, identity in author_files.items():
            file = staged / path
            assert file.is_file(), path
            assert (file.stat().st_size, hashlib.sha256(file.read_bytes()).hexdigest()) == identity, path
        assert inspect_package(staged).manifest.mod_id == GENERIC_JOBS_ID
        for name in ('High', 'Low', 'Disabled'):
            shutil.rmtree(f.staging / name)
        (f.profile / 'modlist.txt').write_text('+Generic Jobs\n')
        receipt, root, manifest = passed(f, OperationKind.SETUP)
        assert manifest['schema_version'] == 3
        assert len(receipt.data['mod_states']) == 1
        assert manifest['user_packages'][0]['mod_id'] == GENERIC_JOBS_ID
        assert manifest['user_packages'][0]['content_manifest_sha256'] == staged_identity
        store = stores_for(manifest)[GENERIC_JOBS_ID]
        assert store.policy.contract['entry_points'] == [
            ['ModDll', 'GenericJobs.dll'], ['ModR2RManagedDll32', 'x86/GenericJobs.dll'],
            ['ModR2RManagedDll64', 'x64/GenericJobs.dll']]
        assert store.policy.contract['dependencies'] == list(inspected.manifest.dependencies)
        for path, identity in author_files.items():
            file = root / 'Mods' / GENERIC_JOBS_ID / path
            assert file.is_file(), path
            assert (file.stat().st_size, hashlib.sha256(file.read_bytes()).hexdigest()) == identity, path
        enhanced = json.loads((root / 'Apps/fft_enhanced.exe/AppConfig.json').read_text())
        classic = json.loads((root / 'Apps/fft_classic.exe/AppConfig.json').read_text())
        assert enhanced['EnabledMods'][:len(MANAGED_ORDER)] == list(MANAGED_ORDER)
        assert enhanced['EnabledMods'][-1] == GENERIC_JOBS_ID
        assert GENERIC_JOBS_ID not in classic['EnabledMods']
        assert not (root / f'Mods/{GENERIC_JOBS_ID}/x86/GenericJobs.dll').exists()
        assert not (root / f'Mods/{GENERIC_JOBS_ID}/x64/GenericJobs.dll').exists()
        assert json.loads((root / f'Mods/{GENERIC_JOBS_ID}/ModConfig.json').read_text())['ModDll'] == 'GenericJobs.dll'
        assert f.composition.mod_state_pending() is None

        write(root, store.policy.user + 'settings.json', b'{"enabled":true}')
        receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)
        assert (root / (store.policy.user + 'settings.json')).read_bytes() == b'{"enabled":true}'
        assert not f.composition.mod_state_pending()
        prior_head = stores_for(manifest)[GENERIC_JOBS_ID].head()
        write(root, store.policy.user + 'settings.json', b'{"enabled":false}')
        prior = _owned_state(f)
        def fail(name, _kind):
            if name == 'mod-state:receipt':
                raise RuntimeError('injected state publication failure')
        f.recompose(failure_injector=fail)
        rejected(lambda: f.run(OperationKind.SAVE_MOD_STATE))
        assert _owned_state(f) == prior
        assert stores_for(manifest)[GENERIC_JOBS_ID].head() == prior_head
        f.recompose(failure_injector=None)
        receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)

        other = f.profile.parent / 'other'; other.mkdir()
        (other / 'modlist.txt').write_text('+Generic Jobs\n')
        f.recompose(profile_dir=other)
        _, other_root, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert other_root != root and not (other_root / (store.policy.user + 'settings.json')).exists()
        f.recompose(profile_dir=f.profile)
        (f.profile / 'modlist.txt').write_text('-Generic Jobs\n')
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        assert (root / (store.policy.user + 'settings.json')).read_bytes() == b'{"enabled":false}'
        disabled = json.loads((root / 'Apps/fft_enhanced.exe/AppConfig.json').read_text())
        assert GENERIC_JOBS_ID not in disabled['EnabledMods']
        assert manifest_digest(content_manifest(staged)) == staged_identity
        write(root, store.policy.user + 'last.bin', b'last state')
        passed(f, OperationKind.REMOVE)
        assert manifest_digest(content_manifest(staged)) == staged_identity
        assert any((export / 'payload' / (store.policy.user + 'last.bin')).read_bytes() == b'last state'
                   for export in f.inputs.quarantine_root.glob('mod-user-state-*')
                   if (export / 'payload' / (store.policy.user + 'last.bin')).is_file())
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == GENERIC_JOBS_SHA256
        print('PASS exact Generic Jobs archive, production generation, state, isolation, disable, rollback and export')
    finally:
        shutil.rmtree(f.root)


def test_large_managed_state(archive=None):
    """Exercise the measured layout count, without treating native DLLs as accepted."""
    with tempfile.TemporaryDirectory(prefix='fftic-large-state-') as tmp:
        root = Path(tmp)
        pristine = package(root / 'pristine', 'author.large-layouts')
        layouts = pristine / 'Nex/Layouts'
        if archive:
            archive = Path(archive).resolve(strict=True)
            assert archive.stat().st_size == 2474233
            assert hashlib.sha256(archive.read_bytes()).hexdigest() == NEW_GAME_PLUS_SHA256
            extracted = root / 'unchanged-author-archive'; extracted.mkdir()
            subprocess.run(['7z', 'x', '-y', f'-o{extracted}', str(archive)],
                           check=True, capture_output=True, timeout=30)
            source = extracted / 'Nex/Layouts'
            measured = [p for p in source.rglob('*.layout') if p.is_file()]
            assert len(measured) == 1070
            assert sum(p.stat().st_size for p in measured) == 596372
            shutil.copytree(source, layouts)
        else:
            for index in range(1070):
                write(pristine, f'Nex/Layouts/faith/{index:04}.layout', b'layout')
        assert len(list(layouts.rglob('*.layout'))) == 1070
        profile = root / 'profile'; profile.mkdir()
        store = new_store(profile, pristine)
        policy = store.policy
        assert 1070 < len(policy.seed) <= policy.max_files <= MAX_MANAGED_STATE_FILES
        assert policy.max_files == len(policy.seed) + 256
        pristine_identity = manifest_digest(content_manifest(pristine))
        work = root / 'work'
        shutil.copytree(pristine, work / policy.mod.rstrip('/'))
        baseline = policy._working_scan(work)
        first = store.capture(work, baseline, expected_head=None, process_running=lambda: False)
        head = store.publish(first, expected_head=None, transaction='initial', generation='first',
                             process_running=lambda: False)
        assert len(store.read(first)[0].files) == len(policy.seed)

        relative = sorted(p.relative_to(pristine).as_posix() for p in layouts.rglob('*.layout'))
        changed = policy.mod + relative[0]
        deleted = policy.mod + relative[1]
        write(work, changed, b'user-edited-layout')
        (work / deleted).unlink()
        write(work, policy.user + 'settings.json', b'{"user":true}')
        second = store.capture(work, baseline, expected_head=head, process_running=lambda: False)
        snapshot, payload = store.read(second)
        assert deleted in snapshot.deleted
        assert (payload / changed).read_bytes() == b'user-edited-layout'
        assert (payload / (policy.user + 'settings.json')).read_bytes() == b'{"user":true}'
        rejected(lambda: store.publish(second, expected_head=head, transaction='failed', generation='first',
                                       process_running=lambda: False,
                                       failure_injector=lambda point: (_ for _ in ()).throw(RuntimeError('injected'))
                                       if point == 'head' else None))
        assert store.head() == head and store.read(second)[0] == snapshot
        second_head = store.publish(second, expected_head=head, transaction='saved', generation='first',
                                    process_running=lambda: False)
        export = root / 'export'
        store.export(second, export)
        assert (export / 'payload' / changed).read_bytes() == b'user-edited-layout'
        restored = root / 'restored'
        shutil.copytree(pristine, restored / policy.mod.rstrip('/'))
        policy.restore(snapshot, payload, restored, policy._working_scan(restored))
        assert (restored / changed).read_bytes() == b'user-edited-layout'
        assert not (restored / deleted).exists()
        store.rollback_publication(expected_head=second_head, previous_head=head,
                                   process_running=lambda: False)
        assert store.head() == head and store.read(second)[0] == snapshot
        other = root / 'other-profile'; other.mkdir()
        other_store = new_store(other, pristine)
        assert other_store.head() is None and other_store.root != store.root

        overflow = root / 'overflow'
        shutil.copytree(pristine, overflow / policy.mod.rstrip('/'))
        for index in range(policy.max_files - len(policy.seed) + 1):
            write(overflow, policy.user + f'extra-{index:04}.dat', b'x')
        rejected(lambda: policy.inspect(overflow, baseline))
        excessive = package(root / 'too-many-seeds', 'author.too-many')
        for index in range(MAX_MANAGED_STATE_FILES):
            write(excessive, f'Data/{index:04}.layout', b'seed')
        rejected(lambda: new_store(profile, excessive))
        link = work / (policy.user + 'link.dat'); link.symlink_to(pristine / 'Data/default.json')
        rejected(lambda: policy.inspect(work, baseline))
        link.unlink()
        write(work, policy.user + 'State.dat', b'a')
        write(work, policy.user + 'state.dat', b'b')
        rejected(lambda: policy.inspect(work, baseline))
        assert manifest_digest(content_manifest(pristine)) == pristine_identity
        print('PASS bounded large managed state, changed/deleted layouts, restore, isolation, rollback and export')


def test_real_new_game_plus(archive):
    """Exact release archive through install, generation and retained-state lifecycle."""
    archive = Path(archive).resolve(strict=True)
    assert archive.stat().st_size == 2474233
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == NEW_GAME_PLUS_SHA256
    f = ModFixture('real-new-game-plus')
    try:
        f.recompose(process_running=lambda: False)
        source = f.root / 'author-package'; source.mkdir()
        subprocess.run(['7z', 'x', '-y', f'-o{source}', str(archive)],
                       check=True, capture_output=True, timeout=30)
        author_files = {p.relative_to(source).as_posix(): (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
                        for p in source.rglob('*') if p.is_file()}
        assert len(author_files) == 1118
        inspected = inspect_package(source)
        assert inspected.classification == PackageClassification.ENHANCED_MANAGED_CODE
        assert inspected.manifest.mod_id == 'fftivc.battles.ngplus'
        from fftic_mod_state import contract_for
        assert contract_for(source)['entry_points'] == [['ModDll', 'fftivc.battles.ngplus.dll']]

        from Utils.mods.install import prepare_archive, finish_install
        from final_fantasy_tactics import FinalFantasyTacticsTheIvaliceChronicles
        with patch('Utils.mods.copy.resolve_target_staging', return_value=f.staging), \
             patch('Utils.mods.install._update_indexes'), \
             patch('Utils.mods.install._check_nexus_flags_after_install'):
            prepared = prepare_archive(str(archive), FinalFantasyTacticsTheIvaliceChronicles(),
                                       f.profile, preferred_name='New Game++', log_fn=lambda _: None)
            assert prepared is not None
            assert finish_install(prepared, None, log_fn=lambda _: None) == 'New Game++'
        staged = f.staging / 'New Game++'
        for path, identity in author_files.items():
            file = staged / path
            assert file.is_file(), path
            assert (file.stat().st_size, hashlib.sha256(file.read_bytes()).hexdigest()) == identity, path
        for name in ('High', 'Low', 'Disabled'):
            shutil.rmtree(f.staging / name)
        (f.profile / 'modlist.txt').write_text('+New Game++\n')
        receipt, root, manifest = passed(f, OperationKind.SETUP)
        mod_id = 'fftivc.battles.ngplus'
        assert manifest['schema_version'] == 3
        assert manifest['user_packages'][0]['mod_id'] == mod_id
        assert len(receipt.data['mod_states']) == 1
        assert verify_private_generation(root) == receipt.data['active_generation_identity']['manifest_sha256']
        store = stores_for(manifest)[mod_id]
        assert len(store.policy.seed) > 1070 and store.policy.max_files > 1024
        for path, identity in author_files.items():
            file = root / 'Mods' / mod_id / path
            assert file.is_file(), path
            assert (file.stat().st_size, hashlib.sha256(file.read_bytes()).hexdigest()) == identity, path
        enhanced = json.loads((root / 'Apps/fft_enhanced.exe/AppConfig.json').read_text())
        classic = json.loads((root / 'Apps/fft_classic.exe/AppConfig.json').read_text())
        assert enhanced['EnabledMods'][-1] == mod_id
        assert mod_id not in classic['EnabledMods']

        layouts = sorted((root / 'Mods' / mod_id / 'Nex/Layouts').rglob('*.layout'))
        assert len(layouts) == 1070
        changed = layouts[0].relative_to(root).as_posix()
        deleted = layouts[1].relative_to(root).as_posix()
        write(root, changed, b'changed layout fixture')
        (root / deleted).unlink()
        write(root, store.policy.user + 'user-state.json', b'{"test":1}')
        receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)
        state = stores_for(manifest)[mod_id]
        snapshot, payload = state.read(state.head()['revision'])
        assert deleted in snapshot.deleted
        assert (payload / changed).read_bytes() == b'changed layout fixture'
        assert (payload / (store.policy.user + 'user-state.json')).read_bytes() == b'{"test":1}'
        other = f.profile.parent / 'other'; other.mkdir()
        (other / 'modlist.txt').write_text('+New Game++\n')
        f.recompose(profile_dir=other)
        _, other_root, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert (other_root / changed).read_bytes() == (source / layouts[0].relative_to(root / 'Mods' / mod_id)).read_bytes()
        f.recompose(profile_dir=f.profile)
        _, restored, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert (restored / changed).read_bytes() == b'changed layout fixture'
        assert not (restored / deleted).exists()
        assert (restored / (store.policy.user + 'user-state.json')).read_bytes() == b'{"test":1}'
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == NEW_GAME_PLUS_SHA256
        print('PASS exact New Game++ archive install, generation, capture, profile isolation and restore')
    finally:
        shutil.rmtree(f.root)


if __name__ == '__main__':
    test_application_intersection()
    test_boundary()
    test_production()
    test_large_managed_state(os.environ.get('FFTIC_NEW_GAME_PLUS_ARCHIVE'))
    if os.environ.get('FFTIC_NEW_GAME_PLUS_ARCHIVE'):
        test_real_new_game_plus(os.environ['FFTIC_NEW_GAME_PLUS_ARCHIVE'])
    if os.environ.get('FFTIC_GENERIC_JOBS_ARCHIVE'):
        test_real_generic_jobs(os.environ['FFTIC_GENERIC_JOBS_ARCHIVE'])
    else:
        print('SKIP real Generic Jobs archive (set FFTIC_GENERIC_JOBS_ARCHIVE to the unchanged 0.0.12 asset)')
