"""Isolated retained-state fixtures. No DLL, game, SQLite or Proton execution.

Requires FFTIC_COLOR_330_ARCHIVE; absence is an error, never a passing skip.
These exercise the state backend, not the still-held production lifecycle.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import fftic_color_state
from fftic_color_state import (
    Color330Policy, ColorStateError, ColorStateStore, DB, MOD, USER, NXD, TEX,
    _scan, safe_theme_name,
)
from fftic_extraction import ExtractionLimits, extract_archive
from fftic_packages import PackageClassification, inspect_package, is_reviewed_color_customizer_archive


def refused(fn, text=None):
    try:
        fn()
    except ColorStateError as exc:
        if text:
            assert text in str(exc), str(exc)
    else:
        raise AssertionError('Unsafe state was accepted')


def write(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())


def main():
    archive_value = os.environ.get('FFTIC_COLOR_330_ARCHIVE')
    assert archive_value, 'Set FFTIC_COLOR_330_ARCHIVE to the isolated audited ZIP'
    archive = Path(archive_value)
    assert is_reviewed_color_customizer_archive(archive)
    before = hashlib.sha256(archive.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='color-state-') as temporary:
        root = Path(temporary)
        extracted = extract_archive(archive, root / 'extracted',
                                    limits=ExtractionLimits(1323, 108569077, 1691648))
        package = extracted.root / 'paxtrick.fft.colorcustomizer'
        policy = Color330Policy(package)
        assert inspect_package(package).classification == PackageClassification.DUAL_MODE_MANAGED_CODE
        package_before = _scan(package)
        generation = root / 'generation-a'
        shutil.copytree(package, generation / MOD.rstrip('/'))
        write(generation, 'Loader/unchanged.dll', b'unrelated managed fixture')
        write(generation, 'Apps/fft_enhanced.exe/AppConfig.json', {'immutable': True})
        (generation / 'User/Mods').mkdir(parents=True)
        baseline = policy.initial_manifest(generation)
        profile = root / 'profile-a'
        profile.mkdir()
        store = ColorStateStore(profile, policy)
        stopped = lambda: False
        head = None

        def capture(current=generation, expected=None):
            return store.capture(current, baseline, expected_head=expected, process_running=stopped)

        def publish(revision, previous, tag='save'):
            return store.publish(revision, expected_head=previous, transaction=tag,
                                 generation='generation-a', process_running=stopped)

        # Fresh package seed, first settings write, repeated edits, deletions, restart.
        seed = capture()
        head = publish(seed, None, 'seed')
        assert capture(expected=head) == seed
        write(generation, USER + 'Config.json', {'KnightMale': 'original'})
        write(generation, USER + 'WindowState.json', {'Width': 1200, 'Height': 800})
        write(generation, MOD + 'UserThemes.json', {'Knight_Male': ['My violet']})
        palette = MOD + 'UserThemes/Knight_Male/My violet/palette.bin'
        write(generation, palette, bytes(range(256)) * 2)
        write(generation, MOD + 'UserThemes/Knight_Male/My violet/battle_knight_m_spr_palette.bin', b'c' * 512)
        write(generation, MOD + 'logs/live_log.txt', b'fixture first log\n')
        write(generation, MOD + TEX + 'tex_830.bin', b'fixture TEX output')
        write(generation, MOD + NXD, b'fixture NXD output')
        # Preserve SQLite + sidecar bytes as a unit, without opening the database.
        write(generation, MOD + DB + '-wal', b'fixture WAL')
        write(generation, MOD + DB + '-shm', b'fixture SHM')
        sprite = next(p for p in policy.limits if '/unit/battle_knight_m_spr.bin' in p)
        write(generation, sprite, b'fixture sprite')
        first = capture(expected=head)
        head = publish(first, head, 'first-save')
        assert first != seed
        reopened = ColorStateStore(profile, Color330Policy(package))
        assert reopened.head() == head
        assert reopened.read(first)[0] == policy.inspect(generation, baseline)
        for i in range(3):
            write(generation, USER + 'Config.json', {'KnightMale': 'My violet' if i % 2 else 'original'})
            write(generation, MOD + 'logs/live_log.txt', f'repeated save {i}'.encode())
            revision = capture(expected=head)
            head = publish(revision, head, f'repeated-{i}')
        write(generation, MOD + 'UserThemes.json', {'Knight_Male': []})
        shutil.rmtree(generation / (MOD + 'UserThemes/Knight_Male/My violet'))
        (generation / (MOD + TEX + 'tex_830.bin')).unlink()
        for path in (MOD + DB + '-wal', MOD + DB + '-shm', USER + 'WindowState.json'):
            (generation / path).unlink()
        # A deleted shipped output stays absent instead of resurrecting the seed.
        shipped = MOD + NXD
        (generation / shipped).unlink()
        last = capture(expected=head)
        head = publish(last, head, 'deleted')
        assert shipped in store.read(last)[0].deleted
        print('PASS first/repeated writes, deletion, restart and exact seed retention')

        # Replacement and loader update/return state overlays are disposable private copies.
        # No actual production receipt, loader update or activation is claimed here.
        for tag in ('synchronize', 'replacement', 'loader-1.7.5', 'return-1.7.3'):
            destination = root / tag
            shutil.copytree(package, destination / MOD.rstrip('/'))
            write(destination, 'Loader/unchanged.dll', b'unrelated managed fixture')
            write(destination, 'Apps/fft_enhanced.exe/AppConfig.json', {'immutable': True})
            (destination / 'User/Mods').mkdir(parents=True)
            snapshot, payload = store.read(head['revision'])
            policy.restore(snapshot, payload, destination, baseline)
            assert policy.inspect(destination, baseline) == snapshot
            assert not (destination / shipped).exists()
            assert (destination / (USER + 'Config.json')).read_bytes() == (generation / (USER + 'Config.json')).read_bytes()
            assert (destination / sprite).stat().st_ino != (generation / sprite).stat().st_ino
            head = store.publish(head['revision'], expected_head=head, transaction=tag,
                                 generation=tag, process_running=stopped)
        print('PASS synchronization/replacement and loader-labelled overlay/return fixtures')

        other_profile = root / 'profile-b'
        other_profile.mkdir()
        other = ColorStateStore(other_profile, policy)
        assert other.head() is None
        pristine = root / 'pristine-b'
        shutil.copytree(package, pristine / MOD.rstrip('/'))
        write(pristine, 'Loader/unchanged.dll', b'unrelated managed fixture')
        write(pristine, 'Apps/fft_enhanced.exe/AppConfig.json', {'immutable': True})
        (pristine / 'User/Mods').mkdir(parents=True)
        other_revision = other.capture(pristine, baseline, expected_head=None, process_running=stopped)
        other_head = other.publish(other_revision, expected_head=None, transaction='second-profile',
                                   generation='pristine-b', process_running=stopped)
        assert other_revision != seed
        assert store.head() == head
        # Cross-profile payloads fail owner verification even if copied with valid hashes.
        shutil.copytree(store.root / 'revisions' / first, other.root / 'revisions' / first)
        refused(lambda: other.read(first), 'identity')
        shutil.rmtree(other.root / 'revisions' / first)
        print('PASS two profiles, switching, cross-profile rejection')

        # Capture refuses unavailable/running evidence, unknown files/directories,
        # changes outside the package and changes to immutable packaged inputs/code.
        for check in (None, lambda: True, lambda: None):
            refused(lambda: store.capture(generation, baseline, expected_head=head, process_running=check))
        forbidden = [MOD + 'extra.txt', MOD + 'extra.dll', USER + 'extra.json',
                     MOD + 'UserThemes/Unknown/Theme/palette.bin', MOD + 'Data/JobClasses.json',
                     MOD + 'FFTColorCustomizer.dll', MOD + 'runtimes/linux-x64/native/libe_sqlite3.so',
                     MOD + 'FFTIVC/data/enhanced/fftpack/unit/sprites_original/battle_knight_m_spr.bin',
                     'Loader/unchanged.dll']
        for path in forbidden:
            target = generation / path
            original = target.read_bytes() if target.exists() else None
            prior_dirs = {p for p in generation.rglob('*') if p.is_dir()}
            write(generation, path, b'unexpected edit')
            refused(lambda: capture(expected=head))
            assert target.read_bytes() == b'unexpected edit'
            assert store.head() == head
            if original is None:
                target.unlink()
                for directory in sorted({p for p in generation.rglob('*') if p.is_dir()} - prior_dirs, reverse=True):
                    directory.rmdir()
            else:
                target.write_bytes(original)
        extra = generation / (MOD + 'unknown-empty')
        extra.mkdir()
        refused(lambda: capture(expected=head), 'directories')
        extra.rmdir()
        target = generation / (MOD + 'logs/live_log.prev.txt')
        target.symlink_to(generation / (USER + 'Config.json'))
        refused(lambda: capture(expected=head), 'Link')
        target.unlink()
        os.link(generation / (USER + 'Config.json'), target)
        refused(lambda: capture(expected=head), 'hardlink')
        target.unlink()
        extra = store.root / 'unowned.txt'
        extra.write_bytes(b'unknown retained-store entry')
        refused(lambda: capture(expected=head), 'Unknown')
        assert extra.read_bytes() == b'unknown retained-store entry'
        extra.unlink()
        extra_revision = store.root / 'revisions/unowned'
        extra_revision.mkdir()
        refused(lambda: capture(expected=head), 'Unknown')
        assert extra_revision.is_dir()
        extra_revision.rmdir()
        print('PASS unknown files/directories, source/code changes, links and stopped-game gates')

        for theme in ('.', '..', 'Original.', 'NUL', 'COM1.txt', '../outside', 'evil\\name',
                      'trailing ', 'x' * 81, 'x:y'):
            refused(lambda: safe_theme_name(theme))
        for fallback in ('Config.json', 'WindowState.json'):
            write(generation, MOD + fallback, {'KnightMale': 'divergent'} if fallback == 'Config.json'
                  else {'Width': 1000, 'Height': 700})
            if fallback == 'WindowState.json':
                write(generation, USER + fallback, {'Width': 1200, 'Height': 800})
            refused(lambda: capture(expected=head), 'Divergent')
            (generation / (MOD + fallback)).unlink()
            if fallback == 'WindowState.json':
                (generation / (USER + fallback)).unlink()
        write(generation, MOD + 'Config.json', {'KnightMale': 'original'})
        # Byte-identical fallback migration copies are retained without choosing one.
        shutil.copyfile(generation / (MOD + 'Config.json'), generation / (USER + 'Config.json'))
        policy.inspect(generation, baseline)
        (generation / (MOD + 'Config.json')).unlink()
        write(generation, MOD + DB + '-journal', b'journal')
        write(generation, MOD + DB + '-wal', b'wal')
        refused(lambda: capture(expected=head), 'Conflicting SQLite')
        (generation / (MOD + DB + '-journal')).unlink()
        (generation / (MOD + DB + '-wal')).unlink()
        write(generation, MOD + 'UserThemes.json', {'Knight_Male': ['..']})
        refused(lambda: capture(expected=head), 'Unsafe')
        write(generation, MOD + 'UserThemes.json', {'Knight_Male': []})
        with patch('fftic_color_state.MAX_FILES', 1):
            refused(lambda: capture(expected=head), 'budget')
        with patch('fftic_color_state.MAX_REVISIONS', 0):
            write(generation, MOD + 'logs/live_log.txt', b'budget change')
            refused(lambda: capture(expected=head), 'budget')
        print('PASS filename/count limits, fallback conflicts, SQLite sidecar conflict preservation')

        # Two divergent captures from one parent; publication is compare-and-swap.
        parent = head
        revision_a = capture(expected=parent)
        write(generation, MOD + 'logs/live_log.txt', b'divergent revision b')
        revision_b = capture(expected=parent)
        head = publish(revision_a, parent, 'revision-a')
        refused(lambda: publish(revision_b, parent, 'revision-b'), 'Divergent')
        assert store.read(revision_b)
        assert (generation / (MOD + 'logs/live_log.txt')).read_bytes() == b'divergent revision b'
        # Capture using a stale generation-bound parent must also refuse.
        refused(lambda: capture(expected=parent), 'Divergent')
        store.rollback_publication(expected_head=head, previous_head=parent, process_running=stopped)
        head = parent
        print('PASS divergent revisions and exact retained-head rollback')

        # Inject failure at each durable publication boundary; head stays exact.
        revision = capture(expected=head)
        for boundary in ('intent', 'head', 'verified', 'completed'):
            def fail(stage):
                if stage == boundary:
                    raise RuntimeError('injected state publication failure')
            try:
                store.publish(revision, expected_head=head, transaction='injected', generation='new',
                              process_running=stopped, failure_injector=fail)
            except RuntimeError as exc:
                assert 'injected' in str(exc)
            else:
                raise AssertionError('failure injection did not run')
            assert ColorStateStore(profile, policy).head() == head
            assert not (store.root / 'intent.json').exists()
        # Simulate an interruption (BaseException bypasses ordinary rollback).
        class Interrupted(BaseException):
            pass
        def interrupt(stage):
            if stage == 'head':
                raise Interrupted()
        try:
            store.publish(revision, expected_head=head, transaction='interrupted', generation='new',
                          process_running=stopped, failure_injector=interrupt)
        except Interrupted:
            pass
        restarted = ColorStateStore(profile, policy)
        refused(lambda: restarted.capture(generation, baseline, expected_head=restarted.head(),
                                         process_running=stopped), 'Interrupted')
        restarted.rollback_interrupted(process_running=stopped)
        assert restarted.head() == head
        # Mutations during copying cannot publish a mixed snapshot.
        write(generation, MOD + 'logs/live_log.txt', b'concurrent capture unique input')
        copyfile = fftic_color_state._copy_state_file
        immutable = generation / 'Loader/unchanged.dll'
        old_immutable = immutable.read_bytes()
        def concurrent_edit(source, target):
            result = copyfile(source, target)
            immutable.write_bytes(b'concurrent immutable edit')
            return result
        with patch('fftic_color_state._copy_state_file', side_effect=concurrent_edit):
            refused(lambda: capture(expected=head), 'Immutable')
        assert immutable.read_bytes() == b'concurrent immutable edit'
        immutable.write_bytes(old_immutable)
        # Retained payload edits also fail, without resetting the user's bytes.
        retained = store.read(first)[1] / palette
        original_palette = retained.read_bytes()
        retained.write_bytes(b'changed retained palette')
        refused(lambda: store.read(first), 'payload changed')
        assert retained.read_bytes() == b'changed retained palette'
        retained.write_bytes(original_palette)
        print('PASS injected publication failures, concurrent capture and restart recovery/rollback')

        # Outer lifecycle failure after state publication must roll all three references
        # back. These are isolated fixture references, not production FFTIC receipts.
        active, receipt = root / 'active-fixture.json', root / 'receipt-fixture.json'
        write(root, active.name, {'generation': head['generation']})
        write(root, receipt.name, {'state': head})
        previous_active, previous_receipt = active.read_bytes(), receipt.read_bytes()
        new_head = publish(revision, head, 'outer-transaction')
        write(root, active.name, {'generation': 'new-generation'})
        write(root, receipt.name, {'state': new_head})
        try:
            raise RuntimeError('injected after receipt publication')
        except RuntimeError:
            store.rollback_publication(expected_head=new_head, previous_head=head, process_running=stopped)
            active.write_bytes(previous_active)
            receipt.write_bytes(previous_receipt)
        assert active.read_bytes() == previous_active and receipt.read_bytes() == previous_receipt
        assert store.head() == head
        print('PASS isolated outer-transaction reference rollback')

        export = store.export(first, root / 'removed-profile-export')
        assert (export / 'payload' / palette).read_bytes() == bytes(range(256)) * 2
        assert json.loads((export / 'revision.json').read_text())['owner'] == store.owner
        refused(lambda: store.export(first, export), 'already exists')
        # Removal of an isolated generation cannot remove profile-owned state/export.
        shutil.rmtree(root / 'replacement')
        assert reopened.read(first)[0] == store.read(first)[0]
        assert (export / 'payload' / (USER + 'Config.json')).exists()
        assert other.head() == other_head
        assert _scan(package) == package_before
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == before
        print('PASS retained removal export and unchanged archive/package/other-profile bytes')

        # Source-shaped dot-name writer: the author's UI only checks whitespace;
        # SaveTheme checks invalid filename chars but accepts '..'. No mod code is
        # executed. The normalized delete target is the entire UserThemes parent.
        unbounded = root / 'unsafe-writer-fixture'
        write(unbounded, 'UserThemes/Knight_Male/Fresh/palette.bin', b'f' * 512)
        theme_dir = unbounded / 'UserThemes/Knight_Male' / '..'
        write(theme_dir, 'palette.bin', b'x' * 512)
        assert theme_dir.resolve() == unbounded / 'UserThemes'
        shutil.rmtree(theme_dir.resolve())
        assert not (unbounded / 'UserThemes/Knight_Male/Fresh/palette.bin').exists()
        refused(lambda: safe_theme_name('..'))
        # A stopped-game snapshot cannot reconstruct Fresh: no retained revision
        # ever contained it. Hence backend tests cannot justify lifting the hold.
        assert inspect_package(package).classification == PackageClassification.DUAL_MODE_MANAGED_CODE
        print('PASS unsafe dot-name source-shaped deletion evidence; historical strict policy deletion evidence')
    print('All 10 Color Customizer retained-state backend groups passed; historical strict policy; production working-copy tests are separate.')


if __name__ == '__main__':
    main()
