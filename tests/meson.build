#############
# UNITTESTS #
#############

argon2_tests = executable('argon2-tests',
    sources: 'test.c',
    dependencies: argon2_shared_dep,
    install: false)

test('argon2 tests', argon2_tests, timeout: 90)

##########
# GENKAT #
##########

genkat = executable('genkat',
    sources: 'genkat.c',
    dependencies: argon2_genkat_dep,
    install: false)

genkat_test_script = build_machine.system() == 'windows' ? 'kats/test.ps1' : 'kats/test.sh'
genkat_wrapper = find_program([genkat_test_script], required : true)
test('argon2 genkat', genkat_wrapper, args: ['--genkat', genkat.full_path()])

#############
# BENCHMARK #
#############

argon2_benchmark = executable('bench',
    sources: 'bench.c',
    dependencies: argon2_static_dep,
    install: false)

benchmark('argon2 benchmark', argon2_benchmark, timeout: 200)
