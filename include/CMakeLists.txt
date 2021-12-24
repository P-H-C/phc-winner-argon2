# CMakeLists.txt provided by 4eck-qed
file(GLOB SOURCES "*.*")
add_library(argon2_include SHARED ${SOURCES})
set_target_properties(argon2_include PROPERTIES LINKER_LANGUAGE CXX)