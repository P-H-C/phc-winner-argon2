project('argon2',
    'c',
    default_options : [
        'c_std=c89',
        'werror=true',
        'warnlevel=3',
        'libdir=lib'
    ],
    version: '20171227',
    license: ['Apache Public License 2.0'])

conf_data = configuration_data()
conf_data.set('version', meson.project_version())
conf_data.set('soversion', '1')

argon2_incdir = include_directories('include')
install_headers('include/argon2.h')

subdir('man')
subdir('src')
subdir('tool')
subdir('tests')
