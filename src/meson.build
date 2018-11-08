argon2lib_definitions = ['-DA2_VISCTL']
argon2lib_dependencies = []

compiler = meson.get_compiler('c')
if target_machine.system() == 'linux'
    dl_dep = compiler.find_library('dl', required: false)
    if dl_dep.found()
        future_included_glibc_dl = declare_dependency(dependencies: [dl_dep])
        argon2lib_dependencies += [future_included_glibc_dl]
    endif
    rt_dep = compiler.find_library('rt', required: false)
    if rt_dep.found()
        future_included_glibc_rt = declare_dependency(dependencies: [rt_dep])
        argon2lib_dependencies += [future_included_glibc_rt]
    endif
endif

if get_option('multithreading').enabled()
    argon2lib_definitions += ['-DARGON2_NO_THREADS']
else
    thread_dep = dependency('threads')
    argon2lib_dependencies += [thread_dep]
endif

argon2_src = [
    'argon2.c',
    'core.c',
    'blake2/blake2b.c',
    'thread.c',
    'encoding.c'
]

with_optimizations = compiler.compiles(files('opt.c'),
    include_directories: argon2_incdir,
    name: 'Check hardware optimization support')

if with_optimizations
    argon2_src += ['opt.c']
else
    argon2_src += ['ref.c']
endif

###############
# Argon2 libs #
###############

argon2_libs = both_libraries('argon2',
    sources: argon2_src,
    include_directories: argon2_incdir,
    c_args: argon2lib_definitions,
    dependencies: argon2lib_dependencies,
    soversion: conf_data.get('soversion'),
    install: true)

argon2_shared_dep = declare_dependency(dependencies: argon2lib_dependencies,
    include_directories: argon2_incdir,
    compile_args: argon2lib_definitions,
    link_with: argon2_libs.get_shared_lib())

argon2_static_dep = declare_dependency(dependencies: argon2lib_dependencies,
    include_directories: argon2_incdir,
    compile_args: argon2lib_definitions,
    link_with: argon2_libs.get_static_lib())

pkg = import('pkgconfig')
pkg.generate(libraries : argon2_libs,
        subdirs : ['.'],
        extra_cflags: argon2lib_definitions,
        version : meson.project_version(),
        name : 'libargon2',
        url: 'https://github.com/P-H-C/phc-winner-argon2',
        filebase : 'argon2',
        requires: argon2_libs,
        description : 'The password hash Argon2, winner of PHC.')

######################################################
# STATIC for genkat (provide sew points for logging) #
######################################################

argon2libgenkat_definitions = argon2lib_definitions + ['-DGENKAT']

argon2_lib_genkat = static_library('argon2-static-genkat',
    sources: argon2_src,
    include_directories: argon2_incdir,
    c_args: argon2libgenkat_definitions,
    dependencies: argon2lib_dependencies,
    install: false)

argon2_genkat_dep = declare_dependency(dependencies: argon2lib_dependencies,
    include_directories: [argon2_incdir, include_directories('.')],
    compile_args: argon2libgenkat_definitions,
    link_with: argon2_lib_genkat)
