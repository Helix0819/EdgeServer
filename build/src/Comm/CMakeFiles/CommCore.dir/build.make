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
include src/Comm/CMakeFiles/CommCore.dir/depend.make

# Include the progress variables for this target.
include src/Comm/CMakeFiles/CommCore.dir/progress.make

# Include the compile flags for this target's objects.
include src/Comm/CMakeFiles/CommCore.dir/flags.make

src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.o: src/Comm/CMakeFiles/CommCore.dir/flags.make
src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.o: ../src/Comm/sslConnect.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/CommCore.dir/sslConnect.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Comm/sslConnect.cc

src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/CommCore.dir/sslConnect.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Comm/sslConnect.cc > CMakeFiles/CommCore.dir/sslConnect.cc.i

src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/CommCore.dir/sslConnect.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Comm/sslConnect.cc -o CMakeFiles/CommCore.dir/sslConnect.cc.s

# Object files for target CommCore
CommCore_OBJECTS = \
"CMakeFiles/CommCore.dir/sslConnect.cc.o"

# External object files for target CommCore
CommCore_EXTERNAL_OBJECTS =

../lib/libCommCore.a: src/Comm/CMakeFiles/CommCore.dir/sslConnect.cc.o
../lib/libCommCore.a: src/Comm/CMakeFiles/CommCore.dir/build.make
../lib/libCommCore.a: src/Comm/CMakeFiles/CommCore.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library ../../../lib/libCommCore.a"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && $(CMAKE_COMMAND) -P CMakeFiles/CommCore.dir/cmake_clean_target.cmake
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CommCore.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/Comm/CMakeFiles/CommCore.dir/build: ../lib/libCommCore.a

.PHONY : src/Comm/CMakeFiles/CommCore.dir/build

src/Comm/CMakeFiles/CommCore.dir/clean:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm && $(CMAKE_COMMAND) -P CMakeFiles/CommCore.dir/cmake_clean.cmake
.PHONY : src/Comm/CMakeFiles/CommCore.dir/clean

src/Comm/CMakeFiles/CommCore.dir/depend:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cluster/JunWu/Cloud-Edge/EdgeServer /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Comm /home/cluster/JunWu/Cloud-Edge/EdgeServer/build /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Comm/CMakeFiles/CommCore.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/Comm/CMakeFiles/CommCore.dir/depend

