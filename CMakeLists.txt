cmake_minimum_required(VERSION 3.10)
project(WebSocketJSONTest VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost
find_package(Boost REQUIRED COMPONENTS system thread)

add_executable(my_executable src/main.cpp)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})

# Link against Boost libraries
target_link_libraries(my_executable ${Boost_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(my_executable OpenSSL::SSL OpenSSL::Crypto)