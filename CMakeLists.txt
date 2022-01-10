project(bcrypt-test C)
add_executable(a test_bcrypt.c)
target_link_libraries(a bcrypt)
