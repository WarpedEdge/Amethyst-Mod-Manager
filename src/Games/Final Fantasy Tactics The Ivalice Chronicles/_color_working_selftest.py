"""Exact unchanged ZIP through isolated production services; never runs binaries."""
import hashlib
import json
import os
import shutil
from dataclasses import replace
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

# Confine shared installer/config lookups before importing production handlers.
import _selftest
from _c3c_selftest import Fixture, _owned_state
from fftic_color_state import MOD, USER, DB, NXD, working_store, working_baseline, reviewed_source_archive, ColorStateStore, Color330Policy
from fftic_extraction import ExtractionLimits, extract_archive
from fftic_generation import verify_private_generation, content_manifest, manifest_digest
from fftic_managed_executor import OperationState
from fftic_orchestration import OperationKind
from fftic_packages import inspect_package, is_reviewed_color_customizer_archive
from fftic_receipts import read_receipt
from fftic_artifacts import ARTIFACTS, REVIEWED_LOADER_UPDATE
from fftic_workflows import ReviewedCandidateSet
from fftic_loader_releases import CHECKER, parse_release
from _loader_update_selftest import metadata

ARCHIVE = Path(os.environ['FFTIC_COLOR_330_ARCHIVE'])
assert is_reviewed_color_customizer_archive(ARCHIVE)
ARCHIVE_HASH = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()


class ColorFixture(Fixture):
    def plan(self, kind):
        plan = super().plan(kind)
        if kind == OperationKind.UPDATE:
            plan = replace(plan, release=parse_release(metadata(), '1.7.3'))
        return replace(plan, binding=replace(plan.binding, profile_dir=str(self.inputs.profile_dir),
                                            staging_root=str(self.inputs.staging_root)))


def install(f):
    from final_fantasy_tactics import FinalFantasyTacticsTheIvaliceChronicles
    from Utils.mods.install import prepare_archive, finish_install
    handler = FinalFantasyTacticsTheIvaliceChronicles()
    logs = []
    with ExitStack() as stack:
        stack.enter_context(patch('Utils.mods.copy.resolve_target_staging', return_value=f.staging))
        stack.enter_context(patch('Utils.mods.install._update_indexes'))
        stack.enter_context(patch('Utils.mods.install._check_nexus_flags_after_install'))
        prepared = prepare_archive(str(ARCHIVE), handler, f.profile, log_fn=logs.append)
        assert prepared is not None, logs
        prepared.mod_name = 'Color'
        name = finish_install(prepared, None, log_fn=logs.append)
    assert name == 'Color', logs
    assert inspect_package(f.staging / 'Color').is_user_content, logs
    return logs


def active(f):
    receipt = read_receipt(f.inputs.receipts_root)
    root = Path(receipt.data['active_generation_identity']['root'])
    manifest = json.loads((root / 'amethyst-generation.json').read_text())
    return receipt, root, manifest


def write(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def passed(f, kind):
    result = f.run(kind)
    assert result.state == OperationState.SUCCEEDED, result
    return active(f) if kind != OperationKind.REMOVE else None


def main():
    f = ColorFixture('color-working')
    try:
        f.recompose(process_running=lambda: False)
        extracted = extract_archive(ARCHIVE, f.root / 'color-extract',
                                    limits=ExtractionLimits(1323, 108569077, 1691648))
        source = extracted.root / 'paxtrick.fft.colorcustomizer'
        assert source.is_dir(), list(extracted.root.iterdir())
        assert inspect_package(source).is_user_content
        install(f)
        pristine_hash = manifest_digest(content_manifest(f.staging / 'Color', exclude=('meta.ini',)))
        # Enroll a real revision from the previous strict backend without losing it.
        legacy = f.root / 'historical-workspace'
        shutil.copytree(source, legacy / MOD.rstrip('/'))
        (legacy / 'User/Mods').mkdir(parents=True)
        strict = Color330Policy(source)
        baseline = strict.initial_manifest(legacy)
        write(legacy, USER + 'Config.json', b'{"Knight_Male":"Legacy"}')
        retained = ColorStateStore(f.profile, strict)
        legacy_revision = retained.capture(legacy, baseline, expected_head=None, process_running=lambda: False)
        retained.publish(legacy_revision, expected_head=None, transaction='historical',
                         generation='historical', process_running=lambda: False)
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n+Color\n')
        receipt, root, manifest = passed(f, OperationKind.SETUP)
        assert receipt.data['color_state']['profile'] == str(f.profile)
        assert b'Legacy' in (root / (USER + 'Config.json')).read_bytes()
        assert working_store(manifest).read(legacy_revision)[0]
        assert (working_store(manifest).root / 'revisions' / legacy_revision).is_dir()
        print('PASS exact ZIP setup and profile-owned working-copy receipt', flush=True)
        write(root, USER + 'Config.json', b'{"Knight_Male":"Theme"}')
        write(root, MOD + 'UserThemes.json', b'{"Knight_Male":[".."," Theme. "]}')
        write(root, MOD + 'UserThemes/Knight_Male/ Theme. /palette.bin', b'p' * 512)
        write(root, MOD + DB + '-wal', b'opaque SQLite WAL')
        write(root, MOD + 'logs/alternate.log', b'normal log')
        (root / (MOD + NXD)).unlink()
        verify_private_generation(root)
        assert f.composition.mod_state_pending()
        # State capture cannot confer PAC ownership, even when PAC status differs.
        pac = f.game / 'data/enhanced/modded.pac'
        pac.parent.mkdir(parents=True, exist_ok=True); pac.write_bytes(b'unrelated PAC')
        pac_before = read_receipt(f.inputs.receipts_root).data['generated_pac_baseline']
        passed(f, OperationKind.SAVE_MOD_STATE)
        assert pac.read_bytes() == b'unrelated PAC'
        assert read_receipt(f.inputs.receipts_root).data['generated_pac_baseline'] == pac_before
        pac.unlink()
        assert f.composition.mod_state_pending() is None
        print('PASS opaque settings/theme registry/SQLite/log edits and shipped seed deletion', flush=True)
        # Restart then edit and delete retained files; no resurrection on replacement.
        f.recompose()
        write(root, USER + 'Config.json', b'{"Knight_Male":"Later"}')
        shutil.rmtree(root / (MOD + 'UserThemes'))
        (root / (MOD + DB + '-wal')).unlink()
        passed(f, OperationKind.SAVE_MOD_STATE)
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n-Color\n')
        receipt, root2, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert root2 != root and (root2 / (USER + 'Config.json')).read_bytes().endswith(b'"Later"}')
        assert not (root2 / (MOD + NXD)).exists()
        assert not (root2 / (MOD + 'UserThemes')).exists()
        print('PASS restart, repeated edits/deletion and disabled synchronization', flush=True)
        # Two profiles with identical modlists must never share working bytes.
        other = f.profile.parent / 'other'
        other.mkdir(); (other / 'modlist.txt').write_text((f.profile / 'modlist.txt').read_text())
        other_staging = other / 'mods'
        shutil.copytree(f.staging, other_staging)
        reviewed_source_archive(other_staging, ARCHIVE)
        f.recompose(profile_dir=other, staging_root=other_staging)
        receipt, other_root, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert not (other_root / (USER + 'Config.json')).exists()
        write(other_root, USER + 'Config.json', b'{"Knight_Male":"Other"}')
        passed(f, OperationKind.SAVE_MOD_STATE)
        f.recompose(profile_dir=f.profile, staging_root=f.staging)
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        assert (root / (USER + 'Config.json')).read_bytes().endswith(b'"Later"}')
        print('PASS two profiles, isolation and switch back', flush=True)
        # Capture is recoverable before activation; injected failure restores all heads.
        write(root, MOD + 'logs/alternate.log', b'edited before failure')
        before = _owned_state(f)
        old_head = working_store(manifest).head()
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n+Color\n')
        def fail(name, _kind):
            if name == 'activation':
                raise RuntimeError('injected activation failure')
        f.recompose(failure_injector=fail)
        try:
            f.run(OperationKind.SYNCHRONIZE)
        except RuntimeError as exc:
            assert 'injected activation failure' in str(exc)
        else:
            raise AssertionError('activation injection did not run')
        assert _owned_state(f) == before
        assert working_store(manifest).head() == old_head
        f.recompose(failure_injector=None)
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        print('PASS production activation rollback and retained head recovery', flush=True)
        for boundary in ('color:head', 'color:receipt'):
            if boundary == 'color:receipt':
                write(root, MOD + 'Config.json', (root / (USER + 'Config.json')).read_bytes())
            write(root, MOD + 'logs/alternate.log', boundary.encode())
            before = _owned_state(f)
            old_head = working_store(manifest).head()
            def fail_state(name, _kind):
                if name == boundary:
                    raise RuntimeError('injected ' + boundary)
            f.recompose(failure_injector=fail_state)
            try:
                f.run(OperationKind.SAVE_MOD_STATE)
            except RuntimeError as exc:
                assert 'injected ' + boundary in str(exc)
            else:
                raise AssertionError('state injection did not run')
            assert _owned_state(f) == before
            assert working_store(manifest).head() == old_head
            f.recompose(failure_injector=None)
            receipt, root, manifest = passed(f, OperationKind.SAVE_MOD_STATE)
        assert not (root / (MOD + 'Config.json')).exists()
        print('PASS retained head, migration and receipt publication failure rollback', flush=True)
        # Replacement keeps staging pristine and retains current profile bytes.
        install(f)
        write(root, USER + 'Config.json', b'{"Knight_Male":"Replacement"}')
        (f.profile / 'modlist.txt').write_text('-High\n+Low\n-Disabled\n+Color\n')
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        assert b'Replacement' in (root / (USER + 'Config.json')).read_bytes()
        print('PASS pristine package replacement preserves working state', flush=True)
        # Conflicting fallback/User copies are captured without picking a winner.
        write(root, MOD + 'Config.json', b'{"Knight_Male":"Fallback"}')
        old_head = working_store(manifest).head()
        try:
            f.run(OperationKind.SAVE_MOD_STATE)
        except RuntimeError as exc:
            assert 'Divergent fallback' in str(exc)
        else:
            raise AssertionError('divergent copies were silently selected')
        assert working_store(manifest).head() == old_head
        assert b'Fallback' in (root / (MOD + 'Config.json')).read_bytes()
        (root / (MOD + 'Config.json')).unlink()  # explicit fixture resolution
        passed(f, OperationKind.SAVE_MOD_STATE)
        # Immutable code and unrelated files remain fail closed, with bytes untouched.
        for relative in (MOD + 'FFTColorCustomizer.dll', 'Mods/fixture.high/FFTIVC/data/combined/same.nxd'):
            target = root / relative; old = target.read_bytes(); target.write_bytes(b'changed')
            try:
                verify_private_generation(root)
            except Exception:
                pass
            else:
                raise AssertionError('immutable drift accepted')
            assert target.read_bytes() == b'changed'; target.write_bytes(old)
        target = root / (MOD + 'UserThemes/link'); target.parent.mkdir(exist_ok=True)
        target.symlink_to(f.staging / 'Color')
        try:
            verify_private_generation(root)
        except Exception:
            pass
        else:
            raise AssertionError('linked state accepted')
        target.unlink(); target.parent.rmdir()
        print('PASS fallback conflict snapshot and unrelated-mod/code/link protection', flush=True)
        # A fallback-only saved revision migrates in the replacement copy;
        # original fallback bytes remain recoverable in revision history.
        (root / (USER + 'Config.json')).unlink()
        write(root, MOD + 'Config.json', b'{"Knight_Male":"Migrated"}')
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n+Color\n')
        receipt, root, manifest = passed(f, OperationKind.SYNCHRONIZE)
        assert not (root / (MOD + 'Config.json')).exists()
        assert b'Migrated' in (root / (USER + 'Config.json')).read_bytes()
        write(root, USER + 'Config.json', b'{"Knight_Male":"Replacement"}')
        passed(f, OperationKind.SAVE_MOD_STATE)
        print('PASS fallback-only migration with recoverable original revision', flush=True)
        # Exact managed-loader update and return through the same production methods.
        loader = Path(os.environ['FFTIC_REVIEWED_LOADER_ASSET'])
        shutil.copyfile(loader, f.cache / REVIEWED_LOADER_UPDATE.filename)
        archives = tuple((key, f.cache / (REVIEWED_LOADER_UPDATE if key == 'nenkai-loader' else pin).filename)
                         for key, pin in ARTIFACTS.items() if pin.disposition.value == 'extract')
        f.recompose(setup_candidates=None,
                    update_acquirer=lambda _release, _cancel: ReviewedCandidateSet(archives),
                    revert_acquirer=lambda _cancel: ReviewedCandidateSet(tuple(
                        (key, f.cache / pin.filename) for key, pin in ARTIFACTS.items()
                        if pin.disposition.value == 'extract')))
        with patch.object(CHECKER, 'check', return_value=(parse_release(metadata(), '1.7.3'), '')):
            receipt, root, _ = passed(f, OperationKind.UPDATE)
        assert b'Replacement' in (root / (USER + 'Config.json')).read_bytes()
        write(root, MOD + DB, b'edited database after loader update')
        receipt, root, _ = passed(f, OperationKind.REVERT_LOADER)
        assert (root / (MOD + DB)).read_bytes() == b'edited database after loader update'
        assert b'Replacement' in (root / (USER + 'Config.json')).read_bytes()
        print('PASS managed-loader update and return preserve settings and SQLite output', flush=True)
        write(root, MOD + 'logs/alternate.log', b'final stopped-game edit')
        before = _owned_state(f)
        old_head = working_store(json.loads((root / 'amethyst-generation.json').read_text())).head()
        def fail_remove(name, _kind):
            if name == 'remove:receipt':
                raise RuntimeError('injected remove receipt')
        f.recompose(failure_injector=fail_remove)
        try:
            f.run(OperationKind.REMOVE)
        except RuntimeError as exc:
            assert 'injected remove receipt' in str(exc)
        else:
            raise AssertionError('removal injection did not run')
        assert _owned_state(f) == before
        assert working_store(json.loads((root / 'amethyst-generation.json').read_text())).head() == old_head
        f.recompose(failure_injector=None)
        passed(f, OperationKind.REMOVE)
        exports = list(f.inputs.quarantine_root.glob('color-user-state-*'))
        assert len(exports) == 2 and (exports[-1] / 'revision.json').is_file()
        assert b'Replacement' in (exports[-1] / 'payload' / (USER + 'Config.json')).read_bytes()
        assert (other / '.fftic-color-330/head.json').is_file()
        assert manifest_digest(content_manifest(f.staging / 'Color', exclude=('meta.ini',))) == pristine_hash
        assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == ARCHIVE_HASH
        print('PASS removal inspectable export; archive, staging and other profile preserved', flush=True)
    finally:
        shutil.rmtree(f.root)




def test_large_unrelated_package():
    """State budgets must not be budgets for the entire managed generation."""
    f = ColorFixture('large-unrelated')
    try:
        f.recompose(process_running=lambda: False)
        install(f)
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n+Color\n')
        # Sparse synthetic content, never parsed or executed by a loader.
        large = f.staging / 'High/FFTIVC/data/combined/large.nxd'
        with large.open('wb') as stream:
            stream.truncate(200 * 1024 * 1024)
        receipt, root, _ = passed(f, OperationKind.SETUP)
        write(root, USER + 'Config.json', b'{"Knight_Male":"LargePeer"}')
        passed(f, OperationKind.SAVE_MOD_STATE)
        (f.profile / 'modlist.txt').write_text('+High\n+Low\n-Disabled\n-Color\n')
        receipt, root, _ = passed(f, OperationKind.SYNCHRONIZE)
        assert (root / (USER + 'Config.json')).read_bytes() == b'{"Knight_Male":"LargePeer"}'
        assert (root / 'Mods/fixture.high/FFTIVC/data/combined/large.nxd').stat().st_size == large.stat().st_size
        print('PASS bounded mod-owned state with a large unrelated package and replacement', flush=True)
    finally:
        shutil.rmtree(f.root)


if __name__ == '__main__':
    main()
    test_large_unrelated_package()
    from _loader_update_production_selftest import test_default_status_to_production_update
    test_default_status_to_production_update(Path(os.environ['FFTIC_REVIEWED_LOADER_ASSET']), with_color=True)
