executable(
  'poc_macsec_dpdk',
  'main.c',
  # DPDK 23.11 public cryptodev headers use GNU zero-length arrays and
  # named variadic macros, so suppress pedantic diagnostics for this target.
  c_args: ['-D_GNU_SOURCE', '-Wno-pedantic'],
  dependencies: [macsec_dep, key_control_dep, dpdk],
  install: false,
)
