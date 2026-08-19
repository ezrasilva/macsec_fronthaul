key_control_lib = static_library(
  'poc_key_control',
  'key_control.c',
  include_directories: include_directories('../../include'),
  dependencies: openssl,
)

key_control_dep = declare_dependency(
  link_with: key_control_lib,
  include_directories: include_directories('../../include'),
  dependencies: openssl,
)

executable(
  'poc_tls_keying',
  'tls_keying.c',
  dependencies: openssl,
  install: false,
)

executable(
  'poc_keyctl',
  'keyctl.c',
  install: false,
)
