cmake_minimum_required(VERSION 3.10)
project(WebSocketChat VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost
find_package(Boost REQUIRED COMPONENTS system thread)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the server executable
add_executable(server server.cpp)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(server ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)

# Add the client executable
add_executable(client client.cpp)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(client ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)