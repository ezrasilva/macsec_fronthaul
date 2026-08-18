macsec_lib = static_library(
  'poc_macsec',
  'macsec.c',
  include_directories: include_directories('../../include'),
  dependencies: openssl,
)

macsec_dep = declare_dependency(
  link_with: macsec_lib,
  include_directories: include_directories('../../include'),
  dependencies: openssl,
)

