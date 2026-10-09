"""Profile-owned Color Customizer state, pristine source and recovery revisions.

Production uses ColorWorkingPolicy for opaque mod-owned data. Color330Policy
retains the historical stricter schema for prior fixtures. Publication joins the
caller's receipt/activation transaction; no PAC or SQLite/mod code is executed.
"""
from __future__ import annotations

import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    from .fftic_packages import (
        _COLOR_ID, _COLOR_ARCHIVE_SHA256, _COLOR_FILE_COUNT, _COLOR_TREE_SHA256,
        _COLOR_COMPILED_FILES, COMPILED_RUNTIME_EXTENSIONS,
    )
except ImportError:
    from fftic_packages import (
        _COLOR_ID, _COLOR_ARCHIVE_SHA256, _COLOR_FILE_COUNT, _COLOR_TREE_SHA256,
        _COLOR_COMPILED_FILES, COMPILED_RUNTIME_EXTENSIONS,
    )

MOD = f"Mods/{_COLOR_ID}/"
USER = f"User/Mods/{_COLOR_ID}/"
UNIT = "FFTIVC/data/enhanced/fftpack/"
DB = "Data/nxd/charclut.sqlite"
NXD = "FFTIVC/data/enhanced/nxd/charclut.nxd"
TEX = "FFTIVC/data/enhanced/system/ffto/g2d/"
MAX_FILES = 1024
MAX_BYTES = 64 * 1024 * 1024
MAX_REVISIONS = 64
MAX_RETAINED_BYTES = 256 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")
# These names/bins are source constants at v3.3.0 (MonsterThemeRegistry).
MONSTERS = dict(zip(
    ("Chocobo", "Goblin", "Bomb", "Panther", "Mindflayer", "Skeleton", "Ghost",
     "Ahriman", "Aevis", "Pig", "Treant", "Minotaur", "Malboro", "Behemoth", "Dragon", "Hydra"),
    ("cyoko", "gob", "bom", "hyou", "ika", "sukeru", "yurei", "arli", "tori", "uri",
     "ki", "minota", "mol", "behi", "dora1", "dora2")))


class ColorStateError(RuntimeError):
    """Preserve the observed tree and retained revisions on any conflict."""


def _json(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _path(value):
    if not isinstance(value, str):
        raise ColorStateError("State path must be a string")
    pure = PurePosixPath(value)
    if (not value or pure.is_absolute() or pure.as_posix() != value
            or any(c in value for c in ('\\', ':', '\0'))
            or any(ord(c) < 32 for c in value)
            or any(p in ('', '.', '..') for p in pure.parts) or len(value.encode()) > 4096):
        raise ColorStateError(f"Unsafe state path: {value!r}")
    return pure


def safe_theme_name(value):
    """Conservative Windows component; refusal never renames a user theme."""
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > 80
            or value != value.strip() or value.endswith('.')
            or value in ('.', '..') or any(ord(c) < 32 for c in value)
            or any(c in value for c in '<>:"/\\|?*')
            or value.split('.')[0].upper() in {
                'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                *(f'LPT{i}' for i in range(1, 10))}):
        raise ColorStateError(f"Unsafe or overlong theme name: {value!r}")
    return value


def _canonical(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ColorStateError(f"Linked or noncanonical state root: {path}")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ColorStateError(f"Linked state ancestor: {parent}")
    return path


def _scan(root, *, max_files=8192, max_bytes=192 * 1024 * 1024):
    """Bound traversal before hashing; never follow links or accept hardlinks."""
    root = _canonical(root)
    if not root.is_dir():
        raise ColorStateError(f"Missing state directory: {root}")
    files, dirs, seen = {}, set(), set()
    entries, total = 0, 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > max_files * 4:
                    raise ColorStateError("State directory entry limit exceeded")
                path = Path(child.path)
                relative = path.relative_to(root).as_posix()
                _path(relative)
                if relative.casefold() in seen:
                    raise ColorStateError(f"State case collision: {relative}")
                seen.add(relative.casefold())
                info = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    dirs.add(relative)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    if len(files) >= max_files or total > max_bytes:
                        raise ColorStateError("State file/count/byte limit exceeded")
                    files[relative] = (info.st_size, _file_hash(path, info))
                else:
                    raise ColorStateError(f"Link, hardlink or special state file: {relative}")
    return files, dirs


def _open_regular(path):
    """Walk with directory FDs so a swapped ancestor cannot redirect a read."""
    path = Path(path).absolute()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise ColorStateError(f"Not an unlinked regular file: {path}")
        return fd, info
    except OSError as exc:
        raise ColorStateError(f"Cannot read regular state file: {path}") from exc
    finally:
        os.close(directory)


def _file_hash(path, expected=None):
    fd, info = _open_regular(path)
    with os.fdopen(fd, 'rb') as stream:
        if expected is not None and (info.st_dev, info.st_ino, info.st_size) != (
                expected.st_dev, expected.st_ino, expected.st_size):
            raise ColorStateError('State file changed before hashing')
        h = hashlib.sha256()
        total = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            total += len(chunk)
            if total > info.st_size:
                raise ColorStateError('State file grew while hashing')
            h.update(chunk)
        if total != info.st_size or os.fstat(stream.fileno()).st_mtime_ns != info.st_mtime_ns:
            raise ColorStateError('State file changed while hashing')
        return h.hexdigest()


def _read_regular(path, limit):
    fd, info = _open_regular(path)
    with os.fdopen(fd, 'rb') as stream:
        if info.st_size > limit:
            raise ColorStateError(f'Oversized state file: {path}')
        data = stream.read(limit + 1)
        if len(data) != info.st_size or os.fstat(stream.fileno()).st_mtime_ns != info.st_mtime_ns:
            raise ColorStateError('State file changed while reading')
        return data


def _copy_state_file(source, target):
    _atomic(Path(target), _read_regular(source, MAX_BYTES))


def _parents(paths):
    return {str(parent) for value in paths for parent in PurePosixPath(value).parents
            if str(parent) != '.'}


def _load_json(path, limit=1024 * 1024):
    if (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1
            or path.stat().st_size > limit):
        raise ColorStateError(f"Missing, linked or oversized JSON: {path}")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ColorStateError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(_read_regular(path, limit), object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as exc:
        raise ColorStateError(f"Invalid state JSON: {path}") from exc


@dataclass(frozen=True)
class ColorSnapshot:
    files: tuple[tuple[str, int, str], ...]
    deleted: tuple[str, ...]
    directories: tuple[str, ...]


class Color330Policy:
    """Derive literal paths only from a rehashed exact pristine release tree."""

    def __init__(self, pristine_package):
        self.package = _canonical(pristine_package)
        files, dirs = _scan(self.package)
        inventory = ''.join(f'{path}\0{size}\0{digest}\n'
                            for path, (size, digest) in sorted(files.items()))
        compiled = {path: value for path, value in files.items()
                    if PurePosixPath(path).suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS}
        if (len(files) != _COLOR_FILE_COUNT or dirs != _parents(files)
                or compiled != _COLOR_COMPILED_FILES or _digest(inventory.encode()) != _COLOR_TREE_SHA256):
            raise ColorStateError("State policy requires the complete unchanged reviewed release")
        self.package_files = files
        self.package_dirs = dirs
        self.jobs = {}
        outputs = {}
        jobs = _load_json(self.package / 'Data/JobClasses.json')['jobClasses']
        stories = _load_json(self.package / 'Data/StoryCharacters.json')['characters']
        for job in jobs:
            name, sprite = job['name'], job['spriteName']
            unit = 'unit_psp' if name.startswith(('DarkKnight', 'OnionKnight')) else 'unit'
            self.jobs[name] = {Path(sprite).stem + '_palette.bin'}
            outputs[UNIT + unit + '/' + sprite] = 1024 * 1024
        for story in stories:
            name = story['name']
            sprites = [f'battle_{sprite}_spr.bin' for sprite in story['spriteNames']]
            self.jobs[name] = {Path(sprite).stem + '_palette.bin' for sprite in sprites}
            for sprite in sprites:
                outputs[UNIT + 'unit/' + sprite] = 1024 * 1024
        for name, sprite in MONSTERS.items():
            filename = f'battle_{sprite}_spr.bin'
            self.jobs[name] = {Path(filename).stem + '_palette.bin'}
            outputs[UNIT + 'unit/' + filename] = 1024 * 1024
        outputs.update({DB: 8 * 1024 * 1024, NXD: 8 * 1024 * 1024})
        outputs.update({DB + suffix: 8 * 1024 * 1024 for suffix in ('-journal', '-wal', '-shm')})
        outputs.update({TEX + f'tex_{i}.bin': 1024 * 1024 for i in range(830, 836)})
        outputs.update({'Config.json': 1024 * 1024, 'WindowState.json': 4096,
                        'UserThemes.json': 1024 * 1024,
                        'logs/live_log.txt': 8 * 1024 * 1024,
                        'logs/live_log.prev.txt': 8 * 1024 * 1024})
        self.limits = {MOD + path: size for path, size in outputs.items()}
        self.limits.update({USER + 'Config.json': 1024 * 1024, USER + 'WindowState.json': 4096})
        self.seed = {MOD + path: value for path, value in files.items() if MOD + path in self.limits}
        if _scan(self.package) != (files, dirs):
            raise ColorStateError('Pristine release changed while deriving the state policy')

    def _limit(self, path):
        if path in self.limits:
            return self.limits[path]
        if path.startswith(MOD + 'UserThemes/'):
            parts = _path(path[len(MOD):]).parts
            if len(parts) == 4:
                _, job, theme, filename = parts
                safe_theme_name(theme)
                if (job in self.jobs and theme.casefold() != 'original'
                        and filename in {'palette.bin', *self.jobs[job]}):
                    return 512
        raise ColorStateError(f"Unknown mutable path: {path}")

    def initial_manifest(self, generation):
        """Input must already pass the manager's immutable-generation verifier."""
        files, dirs = _scan(generation)
        observed = {path[len(MOD):]: value for path, value in files.items() if path.startswith(MOD)}
        observed_dirs = {path[len(MOD):] for path in dirs if path.startswith(MOD)}
        if observed != self.package_files or observed_dirs != self.package_dirs:
            raise ColorStateError("Initial generation does not contain the pristine release")
        # No unbound User config may be silently adopted at enrollment.
        if any(path.startswith(USER) for path in files):
            raise ColorStateError("Initial generation already contains unbound user state")
        return files, dirs

    def inspect(self, generation, baseline):
        files, dirs = _scan(generation)
        original, original_dirs = baseline
        allowed = {}
        for path, value in files.items():
            if path in self.limits or path.startswith(MOD + 'UserThemes/'):
                limit = self._limit(path)
                if value[0] > limit:
                    raise ColorStateError(f"Mutable file exceeds limit: {path}")
                allowed[path] = value
            elif original.get(path) != value:
                raise ColorStateError(f"Immutable or unexpected generation file: {path}")
        for path in original:
            if path not in files and path not in self.limits:
                raise ColorStateError(f"Immutable generation file missing: {path}")
        self._validate_inputs(Path(generation), allowed)
        dynamic_dirs = _parents(allowed)
        dynamic_dirs.update({MOD.rstrip('/'), USER.rstrip('/'), MOD + 'logs', MOD + 'UserThemes'})
        dynamic_dirs.update({MOD + 'UserThemes/' + job for job in self.jobs})
        if dirs - original_dirs - dynamic_dirs:
            raise ColorStateError(f"Unexpected generation directories: {sorted(dirs - original_dirs - dynamic_dirs)}")
        deleted = tuple(sorted(path for path in self.seed if path not in allowed))
        state_dirs = tuple(sorted(dirs - original_dirs))
        snapshot = ColorSnapshot(tuple((path, *value) for path, value in sorted(allowed.items())),
                                 deleted, state_dirs)
        self.validate_snapshot(snapshot)
        return snapshot

    def _validate_inputs(self, generation, files):
        for path in (MOD + 'Config.json', USER + 'Config.json'):
            if path in files:
                data = _load_json(generation / path)
                if not isinstance(data, dict) or any(not isinstance(k, str) for k in data):
                    raise ColorStateError("Config must be an object of theme selections")
                for value in data.values():
                    if value is not None:
                        safe_theme_name(value)
        for name in ('Config.json', 'WindowState.json'):
            left, right = MOD + name, USER + name
            if left in files and right in files and files[left] != files[right]:
                raise ColorStateError(f"Divergent fallback and User {name}; preserve both")
        for path in (MOD + 'WindowState.json', USER + 'WindowState.json'):
            if path in files:
                value = _load_json(generation / path, 4096)
                if (not isinstance(value, dict) or set(value) != {'Width', 'Height'}
                        or any(type(v) is not int or not 0 < v <= 32768 for v in value.values())):
                    raise ColorStateError("Window state is outside the bounded schema")
        registry_path = MOD + 'UserThemes.json'
        registry = _load_json(generation / registry_path) if registry_path in files else {}
        if not isinstance(registry, dict) or len(registry) > len(self.jobs):
            raise ColorStateError("Theme registry must be a bounded job map")
        themes, count = set(), 0
        for job, names in registry.items():
            if job not in self.jobs or not isinstance(names, list) or len(names) > 64:
                raise ColorStateError(f"Unknown job or theme count: {job}")
            seen = set()
            for name in names:
                safe_theme_name(name)
                if name.casefold() == 'original' or name.casefold() in seen:
                    raise ColorStateError("Reserved or case-colliding user theme")
                seen.add(name.casefold())
                count += 1
                themes.add((job, name))
                palette = MOD + f'UserThemes/{job}/{name}/palette.bin'
                if palette not in files or files[palette][0] != 512:
                    raise ColorStateError(f"Incomplete user theme: {job}/{name}")
        if count > 256:
            raise ColorStateError("Profile theme count exceeds 256")
        for path, (size, _) in files.items():
            if path.startswith(MOD + 'UserThemes/'):
                _, job, theme, _ = _path(path[len(MOD):]).parts
                if (job, theme) not in themes or size != 512:
                    raise ColorStateError(f"Orphan or invalid theme palette: {path}")
        sidecars = [MOD + DB + suffix for suffix in ('-journal', '-wal', '-shm')]
        if any(path in files for path in sidecars) and MOD + DB not in files:
            raise ColorStateError("SQLite sidecar without its working database")
        if sidecars[2] in files and sidecars[1] not in files:
            raise ColorStateError('SQLite SHM without its WAL')
        if sidecars[0] in files and any(path in files for path in sidecars[1:]):
            raise ColorStateError("Conflicting SQLite rollback and WAL sidecars")

    def validate_snapshot(self, snapshot):
        if len(snapshot.files) > MAX_FILES or sum(size for _, size, _ in snapshot.files) > MAX_BYTES:
            raise ColorStateError("Mutable snapshot budget exceeded")
        paths = []
        for path, size, digest in snapshot.files:
            _path(path)
            if type(size) is not int or size < 0 or size > self._limit(path) or not _HASH.fullmatch(digest):
                raise ColorStateError("Invalid mutable snapshot record")
            paths.append(path)
        if paths != sorted(set(paths)) or len({p.casefold() for p in paths}) != len(paths):
            raise ColorStateError("Duplicate or noncanonical mutable snapshot")
        if (list(snapshot.deleted) != sorted(set(snapshot.deleted))
                or not set(snapshot.deleted) <= set(self.seed)
                or set(snapshot.deleted) & set(paths)
                or set(self.seed) - set(paths) != set(snapshot.deleted)):
            raise ColorStateError("Mutable deletion inventory is invalid")
        if list(snapshot.directories) != sorted(set(snapshot.directories)):
            raise ColorStateError("Mutable directory inventory is invalid")
        permitted_dirs = _parents(paths) | {MOD + 'logs', MOD + 'UserThemes', USER.rstrip('/')}
        permitted_dirs.update({MOD + 'UserThemes/' + job for job in self.jobs})
        if not set(snapshot.directories) <= permitted_dirs:
            raise ColorStateError("Unexpected retained directory")

    def _pristine_destination(self, generation, baseline):
        return _scan(generation) == baseline

    def restore(self, snapshot, payload_root, generation, baseline):
        """Overlay only a newly copied pristine generation, never an active tree."""
        self.validate_snapshot(snapshot)
        if not self._pristine_destination(generation, baseline):
            raise ColorStateError("Restore destination is not the exact pristine generation")
        expected = {path: (size, digest) for path, size, digest in snapshot.files}
        actual, dirs = _scan(payload_root, max_files=MAX_FILES, max_bytes=MAX_BYTES)
        if actual != expected or dirs != _parents(expected):
            raise ColorStateError("Retained mutable payload drift")
        self._validate_inputs(Path(payload_root), actual)
        for path in snapshot.deleted:
            (Path(generation) / path).unlink()
        for path, _, _ in snapshot.files:
            target = Path(generation) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_state_file(Path(payload_root) / path, target)
        for path in snapshot.directories:
            (Path(generation) / path).mkdir(parents=True, exist_ok=True)
        if self.inspect(generation, baseline) != snapshot:
            raise ColorStateError("Restored mutable state differs")


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        _sync_dir(path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def _publish_directory(source, destination):
    # Amethyst runs on Linux. Fail closed without exclusive rename support;
    # os.rename could replace a concurrently created empty unknown directory.
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as exc:
        raise ColorStateError("Exclusive directory publication is unavailable") from exc
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise ColorStateError(f"Exclusive directory publication refused: {os.strerror(error)}")


class ColorStateStore:
    """Profile-owned immutable revisions with CAS head and durable rollback intent.

    Retention is capped by refusal, not deletion: an export/review is necessary
    when the budget is reached. Interrupted publication blocks further work;
    explicit rollback restores only the exact journaled prior head.
    """

    def __init__(self, profile_dir, policy, *, create=True):
        self.profile = _canonical(profile_dir)
        if not self.profile.is_dir():
            raise ColorStateError("Profile is missing")
        self.policy = policy
        self.root = self.profile / '.fftic-color-330'
        self.owner = {'schema': 1, 'profile': str(self.profile), 'mod_id': _COLOR_ID,
                      'archive_sha256': _COLOR_ARCHIVE_SHA256}
        if not self.root.exists():
            if not create:
                raise ColorStateError('Retained state is missing; recovery required')
            self.root.mkdir()
            (self.root / 'revisions').mkdir()
            _atomic(self.root / 'owner.json', _json(self.owner))
            _sync_dir(self.profile)
        _canonical(self.root)
        if _load_json(self.root / 'owner.json') != self.owner:
            raise ColorStateError("Retained state has a different profile or release owner")
        allowed = {'owner.json', 'revisions', 'head.json', 'intent.json', 'lock'}
        if any(p.name not in allowed or p.is_symlink() for p in self.root.iterdir()):
            raise ColorStateError("Unknown or linked retained-store entry")
        _canonical(self.root / 'revisions')

    @contextlib.contextmanager
    def _lock(self):
        _canonical(self.root)
        _canonical(self.root / 'revisions')
        if _load_json(self.root / 'owner.json') != self.owner:
            raise ColorStateError('Retained-store owner changed')
        allowed = {'owner.json', 'revisions', 'head.json', 'intent.json', 'lock'}
        if any(p.name not in allowed or p.is_symlink() for p in self.root.iterdir()):
            raise ColorStateError('Unknown or linked retained-store entry')
        for index, child in enumerate((self.root / 'revisions').iterdir()):
            if index >= MAX_REVISIONS:
                raise ColorStateError('Retained revision budget exceeded')
            if not _HASH.fullmatch(child.name) or child.is_symlink() or not child.is_dir():
                raise ColorStateError('Unknown retained revision; preserve for inspection')
        path = self.root / 'lock'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ColorStateError("Unsafe retained-store lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError as exc:
            raise ColorStateError("Retained store is busy") from exc
        finally:
            os.close(fd)

    @staticmethod
    def _stopped(process_running):
        if not callable(process_running) or process_running() is not False:
            raise ColorStateError("Stopped-game evidence is required for mutable state")

    def head(self):
        path = self.root / 'head.json'
        if not path.exists() and not path.is_symlink():
            return None
        value = _load_json(path)
        if (not isinstance(value, dict) or set(value) != {'revision', 'transaction', 'generation'}
                or any(not isinstance(value[k], str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', value[k])
                       for k in ('transaction', 'generation'))):
            raise ColorStateError("Invalid retained-state head")
        self.read(value['revision'])
        return value

    def read(self, revision):
        if not isinstance(revision, str) or not _HASH.fullmatch(revision):
            raise ColorStateError("Invalid state revision")
        root = self.root / 'revisions' / revision
        _canonical(root)
        record = _load_json(root / 'revision.json')
        if (not isinstance(record, dict) or set(record) != {'owner', 'parent', 'files', 'deleted', 'directories'}
                or record['owner'] != self.owner or _digest(_json(record)) != revision
                or record['parent'] is not None and (not isinstance(record['parent'], str)
                                                       or not _HASH.fullmatch(record['parent']))):
            raise ColorStateError("State revision identity differs")
        try:
            snapshot = ColorSnapshot(tuple(tuple(item) for item in record['files']),
                                     tuple(record['deleted']), tuple(record['directories']))
            self.policy.validate_snapshot(snapshot)
        except (TypeError, ValueError) as exc:
            raise ColorStateError("Invalid retained revision schema") from exc
        expected = {path: (size, digest) for path, size, digest in snapshot.files}
        files, dirs = _scan(root / 'payload', max_files=MAX_FILES, max_bytes=MAX_BYTES)
        if files != expected or dirs != _parents(expected):
            raise ColorStateError("Retained revision payload changed")
        if {p.name for p in root.iterdir()} != {'revision.json', 'payload'}:
            raise ColorStateError("Unexpected retained revision entry")
        self.policy._validate_inputs(root / 'payload', files)
        return snapshot, root / 'payload'

    def capture(self, generation, baseline, *, expected_head, process_running):
        with self._lock():
            self._stopped(process_running)
            if (self.root / 'intent.json').exists():
                raise ColorStateError("Interrupted state publication requires explicit rollback")
            if self.head() != expected_head:
                raise ColorStateError("Divergent state head; runtime edits are preserved")
            snapshot = self.policy.inspect(generation, baseline)
            if expected_head is not None and self.read(expected_head['revision'])[0] == snapshot:
                return expected_head['revision']
            record = {'owner': self.owner, 'parent': expected_head['revision'] if expected_head else None,
                      'files': snapshot.files, 'deleted': snapshot.deleted,
                      'directories': snapshot.directories}
            revision = _digest(_json(record))
            destination = self.root / 'revisions' / revision
            if destination.exists():
                self.read(revision)
                return revision
            self._budget(snapshot)
            stage = Path(tempfile.mkdtemp(prefix='.capture-', dir=self.root / 'revisions'))
            try:
                (stage / 'payload').mkdir()
                for path, _, _ in snapshot.files:
                    target = stage / 'payload' / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _copy_state_file(Path(generation) / path, target)
                (stage / 'revision.json').write_bytes(_json(record))
                # Recheck after copying: no mixed revision or immutable-source drift.
                self._stopped(process_running)
                if self.policy.inspect(generation, baseline) != snapshot:
                    raise ColorStateError("Generation changed during capture")
                files, dirs = _scan(stage / 'payload', max_files=MAX_FILES, max_bytes=MAX_BYTES)
                if files != {p: (s, h) for p, s, h in snapshot.files} or dirs != _parents(files):
                    raise ColorStateError("Mutable files changed during capture")
                for path in stage.rglob('*'):
                    if path.is_file():
                        with path.open('rb') as stream:
                            os.fsync(stream.fileno())
                for path in sorted((p for p in stage.rglob('*') if p.is_dir()), reverse=True):
                    _sync_dir(path)
                _sync_dir(stage)
                _publish_directory(stage, destination)
                _sync_dir(destination.parent)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)
            return revision

    def _budget(self, snapshot):
        total, count = 0, 0
        for child in (self.root / 'revisions').iterdir():
            if not _HASH.fullmatch(child.name) or child.is_symlink():
                raise ColorStateError("Unknown retained revision; preserve for inspection")
            previous, _ = self.read(child.name)
            total += sum(size for _, size, _ in previous.files)
            count += 1
        if count >= MAX_REVISIONS or total + sum(size for _, size, _ in snapshot.files) > MAX_RETAINED_BYTES:
            raise ColorStateError("Retained revision budget reached; export and review before continuing")

    def publish(self, revision, *, expected_head, transaction, generation, process_running,
                failure_injector=None):
        """Publish state head inside the caller's receipt/activation transaction.

        Leaves durable intent on interruption. On ordinary injected failure,
        restore the old head before reporting failure; revisions remain inspectable.
        """
        with self._lock():
            self._stopped(process_running)
            if (self.root / 'intent.json').exists():
                raise ColorStateError("Interrupted state publication requires explicit rollback")
            if self.head() != expected_head:
                raise ColorStateError("Divergent retained revision; refusing publication")
            self.read(revision)
            record = _load_json(self.root / 'revisions' / revision / 'revision.json')
            if (revision != (expected_head['revision'] if expected_head else None)
                    and record['parent'] != (expected_head['revision'] if expected_head else None)):
                raise ColorStateError("Captured state derives from a different revision")
            for value in (transaction, generation):
                if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', value):
                    raise ColorStateError("Invalid publication transaction or generation")
            target = {'revision': revision, 'transaction': transaction, 'generation': generation}
            intent = {'owner': self.owner, 'before': expected_head, 'after': target}
            _atomic(self.root / 'intent.json', _json(intent))
            inject = failure_injector or (lambda _: None)
            try:
                inject('intent')
                self._stopped(process_running)
                _atomic(self.root / 'head.json', _json(target))
                inject('head')
                if self.head() != target:
                    raise ColorStateError("Published state head did not verify")
                inject('verified')
                (self.root / 'intent.json').unlink()
                _sync_dir(self.root)
                inject('completed')
            except Exception:
                if not (self.root / 'intent.json').exists():
                    _atomic(self.root / 'intent.json', _json(intent))
                self._restore_head(expected_head)
                raise
            return target

    def _restore_head(self, previous):
        if previous is None:
            (self.root / 'head.json').unlink(missing_ok=True)
            _sync_dir(self.root)
        else:
            self.read(previous['revision'])
            _atomic(self.root / 'head.json', _json(previous))
        if self.head() != previous:
            raise ColorStateError("State-head rollback did not verify")
        (self.root / 'intent.json').unlink()
        _sync_dir(self.root)

    def rollback_publication(self, *, expected_head, previous_head, process_running):
        """Outer receipt/activation rollback restores its exact prior state head."""
        with self._lock():
            self._stopped(process_running)
            if (self.root / 'intent.json').exists() or self.head() != expected_head:
                raise ColorStateError("State changed after publication; preserve for recovery")
            if previous_head is not None:
                self.read(previous_head['revision'])
            record = _load_json(self.root / 'revisions' / expected_head['revision'] / 'revision.json')
            previous_revision = previous_head['revision'] if previous_head else None
            if expected_head['revision'] != previous_revision and record['parent'] != previous_revision:
                raise ColorStateError('Rollback revision is not the publication parent')
            _atomic(self.root / 'intent.json', _json({
                'owner': self.owner, 'before': previous_head, 'after': expected_head}))
            self._restore_head(previous_head)

    def rollback_interrupted(self, *, process_running):
        with self._lock():
            self._stopped(process_running)
            intent = _load_json(self.root / 'intent.json')
            if (not isinstance(intent, dict) or set(intent) != {'owner', 'before', 'after'}
                    or intent['owner'] != self.owner or self.head() not in (intent['before'], intent['after'])):
                raise ColorStateError("Publication journal or current head conflicts; preserve all state")
            self._restore_head(intent['before'])

    def export(self, revision, destination):
        """Retain an inspectable complete revision; never replace an existing export."""
        with self._lock():
            snapshot, payload = self.read(revision)
            destination = _canonical(destination)
            if destination.is_relative_to(self.root):
                raise ColorStateError('Export must be outside the retained store')
            if os.path.lexists(destination):
                raise ColorStateError("Export destination already exists; preserve it")
            if not destination.parent.is_dir():
                raise ColorStateError("Export parent is missing")
            stage = Path(tempfile.mkdtemp(prefix='.color-export-', dir=destination.parent))
            try:
                (stage / 'payload').mkdir()
                for path, _, _ in snapshot.files:
                    target = stage / 'payload' / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _copy_state_file(payload / path, target)
                _copy_state_file(payload.parent / 'revision.json', stage / 'revision.json')
                for path in stage.rglob('*'):
                    if path.is_file():
                        with path.open('rb') as stream:
                            os.fsync(stream.fileno())
                for path in sorted((p for p in stage.rglob('*') if p.is_dir()), reverse=True):
                    _sync_dir(path)
                _sync_dir(stage)
                if _scan(stage / 'payload', max_files=MAX_FILES, max_bytes=MAX_BYTES)[0] != {
                        p: (s, h) for p, s, h in snapshot.files}:
                    raise ColorStateError("Export copy differs")
                _publish_directory(stage, destination)
                _sync_dir(destination.parent)
            finally:
                if stage.exists():
                    shutil.rmtree(stage)
            return destination


class ColorWorkingPolicy(Color330Policy):
    """Opaque mod-owned state; code, package metadata and unrelated paths stay exact.

    The old policy remains readable for historical fixtures. Production does not
    impose a theme registry schema or predict SQLite's temporary-file lifecycle.
    A mod-internal deletion is retained as deletion, not treated as corruption.
    """

    def __init__(self, pristine_package):
        files, dirs = _scan(pristine_package)
        baseline = ({MOD + p: v for p, v in files.items()}, {MOD + p for p in dirs})
        verified = self.from_baseline(baseline)
        self.__dict__.update(verified.__dict__)

    @classmethod
    def from_baseline(cls, baseline):
        files, dirs = baseline
        package_files = {p[len(MOD):]: v for p, v in files.items() if p.startswith(MOD) and p != MOD + 'meta.ini'}
        inventory = ''.join(f'{p}\0{s}\0{h}\n' for p, (s, h) in sorted(package_files.items()))
        if (len(package_files) != _COLOR_FILE_COUNT
                or _digest(inventory.encode()) != _COLOR_TREE_SHA256
                or {p: v for p, v in package_files.items()
                    if PurePosixPath(p).suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS}
                != _COLOR_COMPILED_FILES):
            raise ColorStateError('Working copy baseline is not the reviewed release')
        policy = cls.__new__(cls)
        policy.package_files = package_files
        policy.package_dirs = {p[len(MOD):] for p in dirs if p.startswith(MOD)}
        policy.seed = {p: v for p, v in files.items() if policy.mutable(p)}
        return policy

    @staticmethod
    def mutable(path):
        pure = _path(path)
        if pure.suffix.casefold() in COMPILED_RUNTIME_EXTENSIONS:
            return False
        if path.startswith(USER):
            return True
        if not path.startswith(MOD):
            return False
        relative = path[len(MOD):]
        if relative in {'Config.json', 'WindowState.json', 'UserThemes.json'}:
            return True
        if relative.startswith(('UserThemes/', 'logs/')):
            return True
        if relative.startswith(DB) and '/' not in relative[len(DB):]:
            return True
        if relative == NXD:
            return True
        parts = PurePosixPath(relative).parts
        if (len(parts) == 6 and parts[:4] == ('FFTIVC', 'data', 'enhanced', 'fftpack')
                and parts[4] in {'unit', 'unit_psp'} and parts[5].endswith('.bin')):
            return True
        if relative.startswith(TEX):
            tail = relative[len(TEX):]
            return tail in {f'tex_{i}.bin' for i in range(830, 836)} or tail.split('/')[0] in {
                'themes', 'active_theme', 'white_heretic', 'black_variant',
                'red_variant', 'test_variant'}
        return False

    def _limit(self, path):
        if not self.mutable(path):
            raise ColorStateError(f'Unknown mutable path: {path}')
        return MAX_BYTES

    def _directory(self, path):
        return (path in {USER.rstrip('/'), MOD + 'UserThemes', MOD + 'logs'}
                or path.startswith((USER, MOD + 'UserThemes/', MOD + 'logs/'))
                or self.mutable(path + '/state.bin'))

    def _validate_inputs(self, generation, files):
        # Preserve opaque bytes, including divergent migration copies, in the
        # revision. Migration decides only after this recoverable capture.
        return

    def _working_scan(self, generation):
        # Bound this mod's workspace, independently of unrelated large packages.
        # The generation verifier owns all remaining code/file identities.
        root = _canonical(generation)
        files, dirs = {}, set()
        for prefix in (MOD, USER):
            child = _canonical(root / prefix.rstrip('/'))
            if prefix == USER and not child.exists():
                continue
            observed, directories = _scan(child)
            files.update({prefix + p: value for p, value in observed.items()})
            dirs.update(prefix + p for p in directories)
            dirs.add(prefix.rstrip('/'))
        return files, dirs

    def _pristine_destination(self, generation, baseline):
        files, dirs = self._working_scan(generation)
        original, original_dirs = baseline
        expected = {p: v for p, v in original.items() if p.startswith((MOD, USER))}
        expected_dirs = {p for p in original_dirs if p.startswith((MOD, USER))
                         or p in {MOD.rstrip('/'), USER.rstrip('/')}}
        return files == expected and dirs == expected_dirs

    def inspect(self, generation, baseline):
        files, dirs = self._working_scan(generation)
        original, original_dirs = baseline
        allowed = {}
        for path, value in files.items():
            if self.mutable(path):
                allowed[path] = value
            elif original.get(path) != value:
                raise ColorStateError(f'Immutable or unrelated working-copy file: {path}')
        for path in original:
            if path.startswith(MOD) and path not in files and not self.mutable(path):
                raise ColorStateError(f'Immutable working-copy file missing: {path}')
        dynamic = _parents(allowed)
        extra = dirs - original_dirs - dynamic
        if any(not self._directory(path) for path in extra):
            raise ColorStateError(f'Unrelated working-copy directories: {sorted(extra)}')
        snapshot = ColorSnapshot(tuple((p, *v) for p, v in sorted(allowed.items())),
                                 tuple(sorted(p for p in original if self.mutable(p) and p not in files)),
                                 tuple(sorted(dirs - original_dirs)))
        self.validate_snapshot(snapshot)
        return snapshot

    def validate_snapshot(self, snapshot):
        if len(snapshot.files) > MAX_FILES or sum(v[1] for v in snapshot.files) > MAX_BYTES:
            raise ColorStateError('Working state budget exceeded; files remain preserved')
        paths = []
        for path, size, digest in snapshot.files:
            if type(size) is not int or not 0 <= size <= self._limit(path) or not _HASH.fullmatch(digest):
                raise ColorStateError('Invalid working state record')
            paths.append(path)
        if paths != sorted(set(paths)) or len({p.casefold() for p in paths}) != len(paths):
            raise ColorStateError('Duplicate working state path')
        if (tuple(sorted(set(snapshot.deleted))) != snapshot.deleted
                or not set(snapshot.deleted) <= set(self.seed)
                or set(snapshot.deleted) & set(paths)
                or set(self.seed) - set(paths) != set(snapshot.deleted)):
            raise ColorStateError('Invalid working state deletions')
        if tuple(sorted(set(snapshot.directories))) != snapshot.directories:
            raise ColorStateError('Invalid working state directories')
        parents = _parents(paths)
        for path in snapshot.directories:
            _path(path)
            if path not in parents and not self._directory(path):
                raise ColorStateError('Unrelated retained directory')

    def migrate_private_copy(self, generation):
        """Caller retains both paths first and journals active-copy migration writes."""
        changed = False
        for name in ('Config.json', 'WindowState.json'):
            fallback, user = Path(generation) / (MOD + name), Path(generation) / (USER + name)
            if fallback.exists():
                data = _read_regular(fallback, MAX_BYTES)
                if user.exists() and _read_regular(user, MAX_BYTES) != data:
                    raise ColorStateError('Divergent fallback migration; preserve both copies')
                user.parent.mkdir(parents=True, exist_ok=True)
                _atomic(user, data)
                fallback.unlink()
                changed = True
        return changed

    def check_migration(self, snapshot):
        files = {p: (s, h) for p, s, h in snapshot.files}
        for name in ('Config.json', 'WindowState.json'):
            left, right = MOD + name, USER + name
            if left in files and right in files and files[left] != files[right]:
                raise ColorStateError(
                    f'Divergent fallback and User {name}; both copies are snapshotted. '
                    'Inspect the retained revision and explicitly resolve the two working-copy files before retrying.')


def working_baseline(manifest):
    files = {r['path']: (r['size'], r['sha256']) for r in manifest['files']}
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode('utf-8')
    files['amethyst-generation.json'] = (len(encoded), _digest(encoded))
    # The builder always creates these empty framework directories.
    return files, _parents(files) | {'User', 'User/Mods'}


def working_store(manifest):
    binding = manifest.get('color_working_copy')
    if binding is None:
        return None
    baseline = working_baseline(manifest)
    return ColorStateStore(Path(binding['profile']), ColorWorkingPolicy.from_baseline(baseline), create=False)


def reviewed_source_archive(staging_root, archive=None, *, profile=False):
    """Retain the original ZIP under an exact staging-collection or profile owner."""
    try:
        from .fftic_packages import is_reviewed_color_customizer_archive
    except ImportError:
        from fftic_packages import is_reviewed_color_customizer_archive
    staging = _canonical(staging_root)
    root = (staging / '.fftic-color-330-profile-source' if profile
            else staging.parent / '.fftic-color-330-source')
    owner = {'schema': 1, 'profile' if profile else 'staging': str(staging),
             'archive_sha256': _COLOR_ARCHIVE_SHA256}
    destination = root / 'Color-Customizer-3.3.0.zip'
    if root.exists() or root.is_symlink():
        _canonical(root)
        if ({p.name for p in root.iterdir()} != {'owner.json', destination.name}
                or _load_json(root / 'owner.json') != owner
                or not is_reviewed_color_customizer_archive(destination)
                or destination.stat().st_nlink != 1):
            raise ColorStateError('Pristine archive store changed; preserve for inspection')
        if archive is not None and not is_reviewed_color_customizer_archive(archive):
            raise ColorStateError('Replacement archive is not the unchanged reviewed ZIP')
        return destination
    if archive is None or not is_reviewed_color_customizer_archive(archive):
        raise ColorStateError('Install the unchanged reviewed ZIP to retain its pristine source before synchronization')
    stage = Path(tempfile.mkdtemp(prefix='.color-source-', dir=root.parent))
    try:
        _copy_state_file(Path(archive), stage / destination.name)
        (stage / 'owner.json').write_bytes(_json(owner))
        if not is_reviewed_color_customizer_archive(stage / destination.name):
            raise ColorStateError('Source archive changed during retention')
        for child in stage.iterdir():
            with child.open('rb') as stream:
                os.fsync(stream.fileno())
        _sync_dir(stage)
        _publish_directory(stage, root)
        _sync_dir(root.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return destination
