add_executable(argon2 "main.c")

target_link_libraries(argon2 PUBLIC argon2-static)

install(TARGETS argon2
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
