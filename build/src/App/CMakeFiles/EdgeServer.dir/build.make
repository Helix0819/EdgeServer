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


# Produce verbose output by default.
VERBOSE = 1

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
CMAKE_SOURCE_DIR = /home/cluster/JunWu/Cloud-Edge/EdgeServer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/cluster/JunWu/Cloud-Edge/EdgeServer/build

# Include any dependencies generated for this target.
include src/App/CMakeFiles/EdgeServer.dir/depend.make

# Include the progress variables for this target.
include src/App/CMakeFiles/EdgeServer.dir/progress.make

# Include the compile flags for this target's objects.
include src/App/CMakeFiles/EdgeServer.dir/flags.make

src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.o: src/App/CMakeFiles/EdgeServer.dir/flags.make
src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.o: ../src/App/dbeServer.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/EdgeServer.dir/dbeServer.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/App/dbeServer.cc

src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/EdgeServer.dir/dbeServer.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/App/dbeServer.cc > CMakeFiles/EdgeServer.dir/dbeServer.cc.i

src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/EdgeServer.dir/dbeServer.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/App/dbeServer.cc -o CMakeFiles/EdgeServer.dir/dbeServer.cc.s

# Object files for target EdgeServer
EdgeServer_OBJECTS = \
"CMakeFiles/EdgeServer.dir/dbeServer.cc.o"

# External object files for target EdgeServer
EdgeServer_EXTERNAL_OBJECTS =

../bin/EdgeServer: src/App/CMakeFiles/EdgeServer.dir/dbeServer.cc.o
../bin/EdgeServer: src/App/CMakeFiles/EdgeServer.dir/build.make
../bin/EdgeServer: ../lib/libEnclaveCore.a
../bin/EdgeServer: ../lib/libUtilCore.a
../bin/EdgeServer: ../lib/libDatabaseCore.a
../bin/EdgeServer: ../lib/libIndexCore.a
../bin/EdgeServer: ../lib/libCommCore.a
../bin/EdgeServer: ../lib/libIASCore.a
../bin/EdgeServer: ../lib/libClientCore.a
../bin/EdgeServer: ../lib/libServerCore.a
../bin/EdgeServer: ../lib/libIndexCore.a
../bin/EdgeServer: ../lib/libServerCore.a
../bin/EdgeServer: ../lib/libUtilCore.a
../bin/EdgeServer: ../lib/libEnclaveCore.a
../bin/EdgeServer: ../lib/libCommCore.a
../bin/EdgeServer: ../lib/libIASCore.a
../bin/EdgeServer: src/App/CMakeFiles/EdgeServer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../../bin/EdgeServer"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/EdgeServer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/App/CMakeFiles/EdgeServer.dir/build: ../bin/EdgeServer

.PHONY : src/App/CMakeFiles/EdgeServer.dir/build

src/App/CMakeFiles/EdgeServer.dir/clean:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App && $(CMAKE_COMMAND) -P CMakeFiles/EdgeServer.dir/cmake_clean.cmake
.PHONY : src/App/CMakeFiles/EdgeServer.dir/clean

src/App/CMakeFiles/EdgeServer.dir/depend:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cluster/JunWu/Cloud-Edge/EdgeServer /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/App /home/cluster/JunWu/Cloud-Edge/EdgeServer/build /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/App/CMakeFiles/EdgeServer.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/App/CMakeFiles/EdgeServer.dir/depend
