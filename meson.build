project(
  'macsec-fronthaul-poc',
  'c',
  version: '0.1.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=true'],
)

openssl = dependency('openssl', required: true)
dpdk = dependency('libdpdk', required: true)

subdir('src/macsec')
subdir('src/keying')
subdir('apps/dpdk')
subdir('tests/unit')
