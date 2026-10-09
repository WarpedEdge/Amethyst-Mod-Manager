"""Generic static/lifecycle/production fixtures. No release binary is executed."""
import _selftest  # Set all shared XDG/profile lookups to disposable roots first.
import json
import os
import shutil
import struct
import tempfile
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from _managed_fixture import managed_bytes
from _c3c_selftest import Fixture, _owned_state, _manifest
from fftic_packages import inspect_package, PackageClassification, is_managed_dll
from fftic_mod_state import new_store, stores_for, working_baseline
from fftic_color_state import ColorStateError
from fftic_generation import verify_private_generation, content_manifest, manifest_digest
from fftic_orchestration import OperationKind
from fftic_managed_executor import OperationState
from fftic_receipts import read_receipt, validate_receipt, ReceiptCorruptError
from fftic_readiness import ReadinessAspect


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


if __name__ == '__main__':
    test_boundary()
    test_production()
