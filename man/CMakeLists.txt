add_custom_target(argon2-man ALL
    COMMAND gzip -c "${CMAKE_SOURCE_DIR}/man/argon2.1" > "${CMAKE_BINARY_DIR}/argon2.1.gz"
    BYPRODUCTS "${CMAKE_BINARY_DIR}/argon2.1.gz"
    DEPENDS
    "${CMAKE_SOURCE_DIR}/man/argon2.1")

install (FILES "${CMAKE_BINARY_DIR}/argon2.1.gz"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man.1")
