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
include src/Client/CMakeFiles/ClientCore.dir/depend.make

# Include the progress variables for this target.
include src/Client/CMakeFiles/ClientCore.dir/progress.make

# Include the compile flags for this target's objects.
include src/Client/CMakeFiles/ClientCore.dir/flags.make

src/Client/CMakeFiles/ClientCore.dir/chunker.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/chunker.cc.o: ../src/Client/chunker.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/chunker.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/chunker.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/chunker.cc

src/Client/CMakeFiles/ClientCore.dir/chunker.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/chunker.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/chunker.cc > CMakeFiles/ClientCore.dir/chunker.cc.i

src/Client/CMakeFiles/ClientCore.dir/chunker.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/chunker.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/chunker.cc -o CMakeFiles/ClientCore.dir/chunker.cc.s

src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.o: ../src/Client/dataRetriever.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/dataRetriever.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataRetriever.cc

src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/dataRetriever.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataRetriever.cc > CMakeFiles/ClientCore.dir/dataRetriever.cc.i

src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/dataRetriever.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataRetriever.cc -o CMakeFiles/ClientCore.dir/dataRetriever.cc.s

src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.o: ../src/Client/dataSender.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/dataSender.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataSender.cc

src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/dataSender.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataSender.cc > CMakeFiles/ClientCore.dir/dataSender.cc.i

src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/dataSender.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/dataSender.cc -o CMakeFiles/ClientCore.dir/dataSender.cc.s

src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.o: ../src/Client/raVerifier.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/raVerifier.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/raVerifier.cc

src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/raVerifier.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/raVerifier.cc > CMakeFiles/ClientCore.dir/raVerifier.cc.i

src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/raVerifier.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/raVerifier.cc -o CMakeFiles/ClientCore.dir/raVerifier.cc.s

src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.o: ../src/Client/restoreWriter.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/restoreWriter.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/restoreWriter.cc

src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/restoreWriter.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/restoreWriter.cc > CMakeFiles/ClientCore.dir/restoreWriter.cc.i

src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/restoreWriter.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/restoreWriter.cc -o CMakeFiles/ClientCore.dir/restoreWriter.cc.s

src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o: src/Client/CMakeFiles/ClientCore.dir/flags.make
src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o: ../src/Client/sessionKeyExchange.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o -c /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/sessionKeyExchange.cc

src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.i"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/sessionKeyExchange.cc > CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.i

src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.s"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client/sessionKeyExchange.cc -o CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.s

# Object files for target ClientCore
ClientCore_OBJECTS = \
"CMakeFiles/ClientCore.dir/chunker.cc.o" \
"CMakeFiles/ClientCore.dir/dataRetriever.cc.o" \
"CMakeFiles/ClientCore.dir/dataSender.cc.o" \
"CMakeFiles/ClientCore.dir/raVerifier.cc.o" \
"CMakeFiles/ClientCore.dir/restoreWriter.cc.o" \
"CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o"

# External object files for target ClientCore
ClientCore_EXTERNAL_OBJECTS =

../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/chunker.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/dataRetriever.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/dataSender.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/raVerifier.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/restoreWriter.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/sessionKeyExchange.cc.o
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/build.make
../lib/libClientCore.a: src/Client/CMakeFiles/ClientCore.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/cluster/JunWu/Cloud-Edge/EdgeServer/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX static library ../../../lib/libClientCore.a"
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && $(CMAKE_COMMAND) -P CMakeFiles/ClientCore.dir/cmake_clean_target.cmake
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ClientCore.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/Client/CMakeFiles/ClientCore.dir/build: ../lib/libClientCore.a

.PHONY : src/Client/CMakeFiles/ClientCore.dir/build

src/Client/CMakeFiles/ClientCore.dir/clean:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client && $(CMAKE_COMMAND) -P CMakeFiles/ClientCore.dir/cmake_clean.cmake
.PHONY : src/Client/CMakeFiles/ClientCore.dir/clean

src/Client/CMakeFiles/ClientCore.dir/depend:
	cd /home/cluster/JunWu/Cloud-Edge/EdgeServer/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/cluster/JunWu/Cloud-Edge/EdgeServer /home/cluster/JunWu/Cloud-Edge/EdgeServer/src/Client /home/cluster/JunWu/Cloud-Edge/EdgeServer/build /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client /home/cluster/JunWu/Cloud-Edge/EdgeServer/build/src/Client/CMakeFiles/ClientCore.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/Client/CMakeFiles/ClientCore.dir/depend

