project(bcrypt-test CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(a test_bcrypt.cpp)
target_link_libraries(a bcrypt)
