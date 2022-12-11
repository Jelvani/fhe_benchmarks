cmake_minimum_required(VERSION 3.16)

project(calculator CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS -gdwarf-3)
find_package(SEAL 4.0.0 EXACT REQUIRED)
add_executable(calculator main.cpp calculator.cpp)
target_link_libraries(calculator SEAL::seal ${CMAKE_DL_LIBS})


