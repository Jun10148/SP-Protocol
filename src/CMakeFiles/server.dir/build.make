# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/seojunlee/SP/SP-Protocol

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/seojunlee/SP/SP-Protocol/src

# Include any dependencies generated for this target.
include CMakeFiles/server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/server.dir/flags.make

CMakeFiles/server.dir/server.cpp.o: CMakeFiles/server.dir/flags.make
CMakeFiles/server.dir/server.cpp.o: server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/seojunlee/SP/SP-Protocol/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/server.dir/server.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/server.dir/server.cpp.o -c /home/seojunlee/SP/SP-Protocol/src/server.cpp

CMakeFiles/server.dir/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/server.dir/server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/seojunlee/SP/SP-Protocol/src/server.cpp > CMakeFiles/server.dir/server.cpp.i

CMakeFiles/server.dir/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/server.dir/server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/seojunlee/SP/SP-Protocol/src/server.cpp -o CMakeFiles/server.dir/server.cpp.s

# Object files for target server
server_OBJECTS = \
"CMakeFiles/server.dir/server.cpp.o"

# External object files for target server
server_EXTERNAL_OBJECTS =

server: CMakeFiles/server.dir/server.cpp.o
server: CMakeFiles/server.dir/build.make
server: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
server: /usr/lib/x86_64-linux-gnu/libboost_thread.so.1.71.0
server: /usr/lib/x86_64-linux-gnu/libcrypto.so
server: /usr/lib/x86_64-linux-gnu/libssl.so
server: /usr/lib/x86_64-linux-gnu/libboost_atomic.so.1.71.0
server: /usr/lib/x86_64-linux-gnu/libcrypto.so
server: CMakeFiles/server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/seojunlee/SP/SP-Protocol/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/server.dir/build: server

.PHONY : CMakeFiles/server.dir/build

CMakeFiles/server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/server.dir/clean

CMakeFiles/server.dir/depend:
	cd /home/seojunlee/SP/SP-Protocol/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/seojunlee/SP/SP-Protocol /home/seojunlee/SP/SP-Protocol /home/seojunlee/SP/SP-Protocol/src /home/seojunlee/SP/SP-Protocol/src /home/seojunlee/SP/SP-Protocol/src/CMakeFiles/server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/server.dir/depend

