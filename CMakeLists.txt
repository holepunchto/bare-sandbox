cmake_minimum_required(VERSION 4.0)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)

project(bare_sandbox C)

add_bare_module(bare_sandbox)

target_sources(
  ${bare_sandbox}
  PRIVATE
    binding.c
)

if(APPLE)
  target_link_libraries(
    ${bare_sandbox}
    PRIVATE
      sandbox
  )
endif()
