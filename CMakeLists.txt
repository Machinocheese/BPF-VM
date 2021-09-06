# Set the minimum version of CMake
cmake_minimum_required (VERSION 2.8.11)
# Set the project name
project(bpf_tool)

# Create a sources variable with a link to all C files to compile
set(SOURCES 
    src/bpf_exec.c
    src/bpf_emu.c
)

# Add an executable with the above sources
add_executable(bpf_tool ${SOURCES})


# Set the directories that should be included in the build command for this target
# when running gcc these will be included as -I/directory/path/
target_include_directories(bpf_tool
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)
