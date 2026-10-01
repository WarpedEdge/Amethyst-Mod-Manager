subdir('archives')
subdir('assets')
subdir('ba2')
subdir('bethesda')
subdir('bg3')
subdir('bsa')
subdir('collections')
subdir('deployment')
subdir('diagnostics')
subdir('downloads')
subdir('environment')
subdir('executables')
subdir('filegraph')
subdir('flatpak')
subdir('fomod')
subdir('fs')
subdir('games')
subdir('github')
subdir('launchers')
subdir('loverslab')
subdir('mo2')
subdir('mods')
subdir('npc')
subdir('plugins')
subdir('processes')
subdir('profiles')
subdir('re_engine')
subdir('saves')
subdir('sharing')
subdir('text')
subdir('ui')
subdir('unreal')
subdir('vfs')
subdir('wine')
subdir('witcher3')
subdir('wizards')
subdir('wabbajack')

identity_conf = configuration_data()
identity_conf.set_quoted('APPLICATION_ID', get_option('application_id'))
identity_conf.set_quoted('DISPLAY_NAME', get_option('display_name'))
identity_conf.set_quoted('FLAVOR', get_option('flavor'))
identity_conf.set_quoted('CONFIG_NAMESPACE', get_option('config_namespace'))
identity_conf.set_quoted(
  'DEFAULT_STAGING_ROOT', get_option('default_staging_root'))
configure_file(
  input: '_build_identity.py.in',
  output: '_build_identity.py',
  configuration: identity_conf,
  install: true,
  install_dir: py.get_install_dir() / 'Utils',
)

py.install_sources(
  '__init__.py',
  'app_log.py',
  'app_identity.py',
  'atomic_write.py',
  'ca_bundle.py',
  'config_paths.py',
  'fs_check.py',
  'hardlink_check.py',
  'memory_cache.py',
  subdir: 'Utils',
)
