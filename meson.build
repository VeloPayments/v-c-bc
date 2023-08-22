project('vcblockchain', 'c', 'cpp',
  version : '0.4.3-snapshot',
  default_options : ['c_std=gnu11', 'cpp_std=c++14', 'buildtype=release'],
  meson_version : '>=0.53.0'
)

message('Using build type: ' + get_option('buildtype'))

force_velo_toolchain = get_option('force_velo_toolchain')

if force_velo_toolchain
  cc = meson.get_compiler('c')
  cc_version = run_command(cc.cmd_array() + ['--version'], check : true).stdout()
  if not cc_version.contains('(velo)')
    error('force_velo_toolchain is set and you arn\'t using the velo toolchain.')
  endif
  cpp = meson.get_compiler('cpp')
  cpp_version = run_command(cpp.cmd_array() + ['--version'], check : true).stdout()
  if not cpp_version.contains('(velo)')
    error('force_velo_toolchain is set and you arn\'t using the velo toolchain.')
  endif
else
  warning('Not using the blessed velo gcc toolchain. Here be dragons.')
endif

add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'c')
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'cpp')

src = run_command('find', './src', '-name', '*.c', check : true).stdout().strip().split('\n')
test_src = run_command('find', './test', '-name', '*.cpp', check : true).stdout().strip().split('\n')

# GTest is currently only used on native x86 builds. Creating a disabler will disable the test exe and test target.
if meson.is_cross_build()
  minunit = disabler()
else
  minunit = dependency('minunit', main : true, required : true, fallback : ['minunit', 'minunit_dep'])
endif

vcmodel = dependency('vcmodel',
  required : true,
  fallback : ['vcmodel', 'vcmodel_dep']
)

vpr = dependency('vpr',
  required : true,
  fallback : ['vpr', 'vpr_dep']
)

if meson.is_cross_build()
  lmdb = disabler()
else
  lmdb = dependency('lmdb',
    required : true,
    fallback : ['lmdb', 'lmdb_dep']
  )
endif

vccrypt = dependency('vccrypt',
  required : true,
  fallback : ['vccrypt', 'vccrypt_dep']
)

vccert = dependency('vccert',
  required : true,
  fallback : ['vccert', 'vccert_dep']
)

vpr_sub = subproject('vpr')
vpr_lib = vpr_sub.get_variable('vpr_lib')
vpr_include = vpr_sub.get_variable('vpr_include')

vccert_sub = subproject('vccert')
vccert_lib = vccert_sub.get_variable('vccert_lib')
vccert_include = vccert_sub.get_variable('vccert_include')

vccrypt_sub = subproject('vccrypt')
vccrypt_lib = vccrypt_sub.get_variable('vccrypt_lib')
vccrypt_include = vccrypt_sub.get_variable('vccrypt_include')

vcmodel_sub = subproject('vcmodel')
vcmodel_include = vcmodel_sub.get_variable('vcmodel_include')

if meson.is_cross_build()
  lmdb_sub = disabler()
  message('lmdb disabled for cross build!')
else
  lmdb_sub = subproject('lmdb')
endif

lmdb_include = lmdb_sub.get_variable('lmdb_inc')
lmdb_lib = lmdb_sub.get_variable('lmdb')

cmake = import('cmake')

minunit_proj = cmake.subproject('minunit')
minunit = minunit_proj.dependency('minunit')

rcpr_proj = cmake.subproject('rcpr')
rcpr = rcpr_proj.dependency('rcpr')
rcpr_lib = rcpr_proj.target('rcpr')
rcpr_test = rcpr_proj.target('testrcpr')
rcpr_test_dep = rcpr_proj.target('test')
rcpr_include = rcpr_proj.include_directories('rcpr')

objects = [
  rcpr_lib.extract_all_objects(),
  vpr_lib.extract_all_objects(),
  vccert_lib.extract_all_objects(),
  vccrypt_lib.extract_all_objects()
]

if lmdb_sub.found() 
  objects += [lmdb_lib.extract_all_objects()]
endif

vcblockchain_lib_deps = [rcpr, vcmodel, vpr, vccert, vccrypt]

if lmdb.found()
  vcblockchain_lib_deps += [lmdb]
endif

vcblockchain_include = include_directories('include')
config_include = include_directories('.')

vcblockchain_include_directories = [
  rcpr_include,
  vcmodel_include,
  vcblockchain_include,
  vpr_include,
  vccert_include,
  vccrypt_include,
]

if lmdb_sub.found()
  vcblockchain_include_directories += [lmdb_include]
endif

vcblockchain_lib = static_library('vcblockchain', src,
  dependencies : vcblockchain_lib_deps,
  include_directories: [vcblockchain_include_directories, config_include],
  objects : objects
)

vcblockchain_dep = declare_dependency(
  link_with : [vcblockchain_lib, rcpr_lib],
  include_directories : vcblockchain_include_directories
)

vcblockchain_test = executable('testvcblockchain', test_src,
  dependencies : [minunit, rcpr, minunit, vpr, vccert, vccrypt, lmdb],
  include_directories: [vcblockchain_include_directories, config_include],
  link_with : vcblockchain_lib
)

test('testvcblockchain', vcblockchain_test)
test('testrcpr', rcpr_test, depends: rcpr_test_dep)

conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
configure_file(
  input : 'config.h.in',
  output : 'config.h',
  configuration : conf_data
)
