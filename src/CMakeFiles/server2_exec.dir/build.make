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
include CMakeFiles/server2_exec.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/server2_exec.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/server2_exec.dir/flags.make

CMakeFiles/server2_exec.dir/server2/server.cpp.o: CMakeFiles/server2_exec.dir/flags.make
CMakeFiles/server2_exec.dir/server2/server.cpp.o: server2/server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/seojunlee/SP/SP-Protocol/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/server2_exec.dir/server2/server.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/server2_exec.dir/server2/server.cpp.o -c /home/seojunlee/SP/SP-Protocol/src/server2/server.cpp

CMakeFiles/server2_exec.dir/server2/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/server2_exec.dir/server2/server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/seojunlee/SP/SP-Protocol/src/server2/server.cpp > CMakeFiles/server2_exec.dir/server2/server.cpp.i

CMakeFiles/server2_exec.dir/server2/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/server2_exec.dir/server2/server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/seojunlee/SP/SP-Protocol/src/server2/server.cpp -o CMakeFiles/server2_exec.dir/server2/server.cpp.s

# Object files for target server2_exec
server2_exec_OBJECTS = \
"CMakeFiles/server2_exec.dir/server2/server.cpp.o"

# External object files for target server2_exec
server2_exec_EXTERNAL_OBJECTS =

server2/server2_exec: CMakeFiles/server2_exec.dir/server2/server.cpp.o
server2/server2_exec: CMakeFiles/server2_exec.dir/build.make
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libboost_system.so.1.71.0
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libboost_filesystem.so.1.71.0
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libboost_thread.so.1.71.0
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libcrypto.so
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libssl.so
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libboost_atomic.so.1.71.0
server2/server2_exec: /usr/lib/x86_64-linux-gnu/libcrypto.so
server2/server2_exec: CMakeFiles/server2_exec.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/seojunlee/SP/SP-Protocol/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable server2/server2_exec"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server2_exec.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/server2_exec.dir/build: server2/server2_exec

.PHONY : CMakeFiles/server2_exec.dir/build

CMakeFiles/server2_exec.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/server2_exec.dir/cmake_clean.cmake
.PHONY : CMakeFiles/server2_exec.dir/clean

CMakeFiles/server2_exec.dir/depend:
	cd /home/seojunlee/SP/SP-Protocol/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/seojunlee/SP/SP-Protocol /home/seojunlee/SP/SP-Protocol /home/seojunlee/SP/SP-Protocol/src /home/seojunlee/SP/SP-Protocol/src /home/seojunlee/SP/SP-Protocol/src/CMakeFiles/server2_exec.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/server2_exec.dir/depend

