cmake_minimum_required(VERSION 3.10)
project(WebSocketChat VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost
find_package(Boost REQUIRED COMPONENTS system filesystem thread)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${Boost_INCLUDE_DIRS})

# Add the server1 executable and set its output directory
add_executable(server1_exec src/server1/server.cpp)
set_target_properties(server1_exec PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/src/server1)
# Link Boost, OpenSSL, and Boost Filesystem
target_link_libraries(server1_exec ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)

# Add the client1 executable and set its output directory
add_executable(client1_exec src/server1/client.cpp)
set_target_properties(client1_exec PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/src/server1)
target_link_libraries(client1_exec ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)

# Add the server2 executable and set its output directory
add_executable(server2_exec src/server2/server.cpp)
set_target_properties(server2_exec PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/src/server2)
# Link Boost, OpenSSL, and Boost Filesystem
target_link_libraries(server2_exec ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)

# Add the client2 executable and set its output directory
add_executable(client2_exec src/server2/client.cpp)
set_target_properties(client2_exec PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/src/server2)
target_link_libraries(client2_exec ${Boost_LIBRARIES} OpenSSL::Crypto OpenSSL::SSL)