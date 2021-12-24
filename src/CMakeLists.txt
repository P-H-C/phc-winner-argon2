# CMakeLists.txt provided by 4eck-qed
file(GLOB SOURCES "*.*")
add_library(argon2_src SHARED ${SOURCES})
set_target_properties(argon2_src PROPERTIES LINKER_LANGUAGE CXX)