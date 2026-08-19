unit_test = executable(
  'test_macsec',
  'test_macsec.c',
  dependencies: macsec_dep,
)

test('macsec-unit', unit_test)

key_control_test = executable(
  'test_key_control',
  'test_key_control.c',
  dependencies: key_control_dep,
)

test('key-control-unit', key_control_test)
