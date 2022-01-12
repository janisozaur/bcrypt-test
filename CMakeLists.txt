project(bcrypt-test)

add_executable(a test_bcrypt.c)
target_link_libraries(a bcrypt)

add_executable(b BCryptExportKey_RSA_test.cpp)
target_link_libraries(b bcrypt)
set_property(TARGET b PROPERTY CXX_STANDARD 17)
