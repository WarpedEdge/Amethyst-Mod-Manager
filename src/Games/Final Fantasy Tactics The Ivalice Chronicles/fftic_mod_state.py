"""Reusable profile working state for user-selected managed Reloaded-II mods.

Legacy Color generations keep their original namespace and serialized identities.
New stores bind the complete pristine package identity, separately from mutable
snapshots. This module never loads mod code or gives capture authority over PACs.
"""
from pathlib import Path, PurePosixPath
import json

try:
    from .fftic_color_state import (ColorWorkingPolicy, ColorStateStore, ColorStateError,
        working_baseline, working_store, _scan, _digest,
        _path, _read_regular, _copy_state_file, MAX_BYTES, _HASH)
    from .fftic_packages import inspect_package, COMPILED_RUNTIME_EXTENSIONS, _safe_identifier, _safe_relative_path, SUPPORTED_APP_IDS, _CODE_FIELDS
except ImportError:
    from fftic_color_state import (ColorWorkingPolicy, ColorStateStore, ColorStateError,
        working_baseline, working_store, _scan, _digest,
        _path, _read_regular, _copy_state_file, MAX_BYTES, _HASH)
    from fftic_packages import inspect_package, COMPILED_RUNTIME_EXTENSIONS, _safe_identifier, _safe_relative_path, SUPPORTED_APP_IDS, _CODE_FIELDS

# Code-like data is never imported from a workspace, even under User. Native
# entry points and external programs still require a separate package policy.
CODE_SUFFIXES = COMPILED_RUNTIME_EXTENSIONS | frozenset({
    '.bat', '.cmd', '.ps1', '.sh', '.py', '.pyc', '.js', '.vbs', '.msi', '.wasm', '.jar'})


def metadata(manifest):
    return {'mod_id': manifest.mod_id, 'version': manifest.version,
            'applications': list(manifest.supported_app_ids),
            'dependencies': list(manifest.dependencies),
            'optional_dependencies': list(manifest.optional_dependencies),
            'entry_points': [list(item) for item in manifest.managed_native_declarations]}


def package_identity(files):
    records = tuple(dict(path=p, size=s, sha256=h) for p, (s, h) in
                    sorted(files.items(), key=lambda item: (item[0].casefold(), item[0])))
    return _digest(json.dumps(records, sort_keys=True, separators=(',', ':')).encode())


def contract_for(package):
    result = inspect_package(package)
    if not result.is_user_content or not result.manifest or not result.manifest.managed_native_declarations:
        raise ColorStateError('Working state requires a validated managed entry package')
    files, _ = _scan(package)
    return {'schema': 1, **metadata(result.manifest), 'package_sha256': package_identity(files)}


class ModWorkingPolicy(ColorWorkingPolicy):
    """Bound opaque mod data; loader metadata and every code payload stay exact."""

    def __init__(self, contract, baseline):
        if (not isinstance(contract, dict) or set(contract) != {
                'schema', 'mod_id', 'version', 'applications', 'dependencies',
                'optional_dependencies', 'entry_points', 'package_sha256'}
                or type(contract['schema']) is not int or contract['schema'] != 1
                or not _safe_identifier(contract['mod_id']) or not _safe_relative_path(contract['mod_id'])):
            raise ColorStateError('Invalid mod working-state contract')
        if (not isinstance(contract['version'], str) or not contract['version'].strip()
                or not isinstance(contract['package_sha256'], str)
                or not _HASH.fullmatch(contract['package_sha256'])):
            raise ColorStateError('Invalid working-state version or package identity')
        for key in ('applications', 'dependencies', 'optional_dependencies'):
            values = contract[key]
            if (not isinstance(values, list) or any(not _safe_identifier(v) for v in values)
                    or len({v.casefold() for v in values}) != len(values)):
                raise ColorStateError(f'Invalid working-state {key}')
        if not contract['applications'] or not set(contract['applications']) <= SUPPORTED_APP_IDS:
            raise ColorStateError('Working-state contract is not FFTIC-only')
        entries = contract['entry_points']
        if (not isinstance(entries, list) or any(not isinstance(e, list) or len(e) != 2
                or e[0] not in _CODE_FIELDS or e[0].startswith('ModNative')
                or not isinstance(e[1], str) or not _safe_relative_path(e[1])
                or PurePosixPath(e[1]).suffix.casefold() != '.dll' for e in entries)
                or len({e[0] for e in entries}) != len(entries)
                or 'ModDll' not in {e[0] for e in entries}):
            raise ColorStateError('Invalid managed working-state entry declarations')
        self.contract = contract
        self.mod = f"Mods/{contract['mod_id']}/"
        self.user = f"User/Mods/{contract['mod_id']}/"
        files, dirs = baseline
        self.package_files = {p[len(self.mod):]: v for p, v in files.items() if p.startswith(self.mod)}
        if package_identity(self.package_files) != contract['package_sha256']:
            raise ColorStateError('Working-state contract differs from pristine package identity')
        if 'ModConfig.json' not in self.package_files or any(e[1] not in self.package_files for e in entries if e[0] == 'ModDll'):
            raise ColorStateError('Working-state baseline lacks its manifest or entry DLL')
        self.package_dirs = {p[len(self.mod):] for p in dirs if p.startswith(self.mod)}
        self.seed = {p: v for p, v in files.items() if self.mutable(p)}

    def mutable(self, path):
        pure = _path(path)
        if not _safe_relative_path(path):
            return False
        if pure.suffix.casefold() in CODE_SUFFIXES:
            return False
        if not path.startswith((self.mod, self.user)):
            return False
        relative = path[len(self.mod):] if path.startswith(self.mod) else path[len(self.user):]
        parts = PurePosixPath(relative).parts
        # Case aliases cannot turn protected names into writable metadata.
        if any(p.casefold() in {'modconfig.json', 'meta.ini'} or
               p.casefold().endswith(('.deps.json', '.runtimeconfig.json', '.runtimeconfig.dev.json'))
               for p in parts):
            return False
        return True

    def _directory(self, path):
        _path(path)
        return _safe_relative_path(path) and (path == self.user.rstrip('/') or path.startswith((self.mod, self.user)))

    def _validate_inputs(self, generation, files):
        for path in files:
            data = _read_regular(Path(generation) / path, MAX_BYTES)
            if data.startswith((b'MZ', b'\x7fELF', b'#!', b'\x00asm', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')):
                raise ColorStateError(f'Executable bytes are outside writable data policy: {path}')

    def inspect(self, generation, baseline):
        snapshot = super().inspect(generation, baseline)
        self._validate_inputs(generation, {p: (s, h) for p, s, h in snapshot.files})
        return snapshot

    def check_migration(self, snapshot):
        # There is no generic convention moving Config.json into User. Keep both
        # independent mod-owned locations; only the historical Color adapter moves it.
        return

    def migrate_private_copy(self, generation):
        return False


class ModStateStore(ColorStateStore):
    def __init__(self, profile, policy, *, create=True):
        owner = {'schema': 2, 'profile': str(Path(profile).absolute()), 'contract': policy.contract}
        # Each version/content identity retains its own revisions and seed deletion
        # semantics. Old stores are never relabeled after an author update.
        namespace = '.fftic-mod-' + _digest(policy.contract['mod_id'].casefold().encode())[:16] + '-' + policy.contract['package_sha256']
        super().__init__(profile, policy, create=create, namespace=namespace, owner=owner)


def new_store(profile, package):
    contract = contract_for(package)
    files, dirs = _scan(package)
    prefix = f"Mods/{contract['mod_id']}/"
    baseline = ({prefix + p: v for p, v in files.items()}, {prefix + p for p in dirs} | {prefix.rstrip('/')})
    return ModStateStore(profile, ModWorkingPolicy(contract, baseline))


def stores_for(manifest):
    result = {}
    legacy = working_store(manifest)
    if legacy:
        result[legacy.owner['mod_id']] = legacy
    baseline = working_baseline(manifest)
    for binding in manifest.get('mod_working_copies', []):
        contract = binding['contract']
        store = ModStateStore(binding['profile'], ModWorkingPolicy(contract, baseline), create=False)
        if contract['mod_id'] in result:
            raise ColorStateError('Duplicate legacy/generic working-state binding')
        result[contract['mod_id']] = store
    return result


def state_receipt(stores):
    return [{'mod_id': key, 'profile': str(store.profile),
             'package_sha256': store.policy.contract['package_sha256'], 'head': store.head()}
            for key, store in sorted(stores.items()) if isinstance(store, ModStateStore)]


def transition_copy(old_store, new_policy, generation):
    """Rebase changed data onto pristine new version; preserve ambiguous conflicts.

    The outgoing snapshot/store stays inspectable. Unchanged shipped seeds use
    the new author's defaults. Changed seeds can transfer only if the new seed
    is unchanged; new code/metadata collisions and changed author defaults refuse.
    """
    snapshot, payload = old_store.read(old_store.head()['revision'])
    old_seed = old_store.policy.seed
    for path, size, digest in snapshot.files:
        value = (size, digest)
        if old_seed.get(path) == value:
            continue
        if not new_policy.mutable(path):
            raise ColorStateError(f'Version transition collides with protected payload: {path}')
        new_seed = new_policy.seed.get(path)
        if new_seed is not None and new_seed not in (old_seed.get(path), value):
            raise ColorStateError(f'Version transition has changed author data and user data: {path}; export and resolve')
        target = Path(generation) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_state_file(payload / path, target)
    for path in snapshot.deleted:
        if not new_policy.mutable(path):
            raise ColorStateError(f'Version deletion collides with protected payload: {path}')
        if path in new_policy.seed:
            if new_policy.seed[path] != old_seed[path]:
                raise ColorStateError(f'Version deletion conflicts with changed author data: {path}')
            (Path(generation) / path).unlink()
    for path in snapshot.directories:
        if not new_policy._directory(path):
            raise ColorStateError(f'Version directory collides with protected payload: {path}')
        (Path(generation) / path).mkdir(parents=True, exist_ok=True)
