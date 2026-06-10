project('xkcp', 'c')

keccak_include_dirs = [
  '.',
  'lib/common/',
  'lib/high/Keccak/',
  'lib/high/Keccak/FIPS202/',
  'lib/low/common/',
  'lib/low/KeccakP-1600/common/',
]

keccak_sources = [
  'lib/high/Keccak/FIPS202/KeccakHash.c',
  'lib/high/Keccak/KeccakSponge.c',
]
keccak_generic_include_dirs = [
  'lib/low/KeccakP-1600/plain-64bits/',
  'lib/low/KeccakP-1600/plain-64bits/SnP/',
  'lib/low/KeccakP-1600-times4/fallback-on1/',
]
keccak_generic_sources = [
  'lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c',
  'lib/low/KeccakP-1600-times4/fallback-on1/KeccakP-1600-times4-on1.c',
]
keccak_avx2_include_dirs = [
  'lib/low/KeccakP-1600/AVX2/',
  'lib/low/KeccakP-1600/AVX2/SnP/',
  'lib/low/KeccakP-1600-times4/AVX2/',
  'lib/low/KeccakP-1600-times4/AVX2/SnP/',
]
keccak_avx2_sources = [
  'lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s',
  'lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-AVX2.c',
]

keccak_avx512_include_dirs = [
  'lib/low/KeccakP-1600/AVX512/',
  'lib/low/KeccakP-1600/AVX512/SnP/',
  'lib/low/KeccakP-1600-times4/AVX512/',
  'lib/low/KeccakP-1600-times4/AVX512/SnP/',
]
keccak_avx512_sources = [
  'lib/low/KeccakP-1600/AVX512/KeccakP-1600-AVX512.s',
  'lib/low/KeccakP-1600-times4/AVX512/KeccakP-1600-times4-AVX512.c',
]

xkcp_c_args = []
if host_machine.cpu_family() == 'x86_64' and host_machine.system() != 'darwin'
  if get_option('avx512_keccak')
    keccak_include_dirs += keccak_avx512_include_dirs
    keccak_sources += keccak_avx512_sources
    xkcp_c_args += ['-mavx512f', '-mavx512vl']
  else
    keccak_include_dirs += keccak_avx2_include_dirs
    keccak_sources += keccak_avx2_sources
  endif
else
  keccak_include_dirs += keccak_generic_include_dirs
  keccak_sources += keccak_generic_sources
endif

xkcp_lib = static_library('xkcp', keccak_sources,
  include_directories : keccak_include_dirs,
  c_args : xkcp_c_args)

xkcp_dep = declare_dependency(
  include_directories : keccak_include_dirs,
  link_with : xkcp_lib
)
