##############################################
#   CMake
##############################################
project(yuneta-tls C)
cmake_minimum_required(VERSION 3.0)
include(CheckIncludeFiles)
include(CheckSymbolExists)

set(CMAKE_INSTALL_PREFIX /yuneta/development/output)

set(INC_DEST_DIR ${CMAKE_INSTALL_PREFIX}/include)
set(LIB_DEST_DIR ${CMAKE_INSTALL_PREFIX}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=c99")

if(CMAKE_BUILD_TYPE MATCHES Debug)
  add_definitions(-DDEBUG)
  option(SHOWNOTES "Show preprocessor notes" OFF)

  if(CMAKE_COMPILER_IS_GNUCC)
    # GCC specific debug options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -ggdb3 -gdwarf-2")
    set(AVOID_VERSION -avoid-version)
  endif(CMAKE_COMPILER_IS_GNUCC)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64)

include_directories(/yuneta/development/output/include)

##############################################
#   Source
##############################################

set (SRCS
    src/yuneta_tls_register.c

    # Tasks
    src/c_task_authenticate.c

    # Services
    src/c_authz.c

    # Protocols
    src/c_connexs.c

    # Mixin uv-gobj
    src/c_tcp1.c
    src/c_tcp_s1.c
)


set (HDRS
    src/yuneta_tls.h
    src/yuneta_tls_version.h
    src/yuneta_tls_register.h

    # Tasks
    src/c_task_authenticate.h

    # Services
    src/c_authz.h

    # Protocols
    src/c_connexs.h

    # Mixin uv-gobj
    src/c_tcp1.h
    src/c_tcp_s1.h
)


##############################################
#   Lib
##############################################
add_library(yuneta-tls ${SRCS} ${HDRS})

##############################################
#   System install
##############################################
install(FILES ${HDRS} DESTINATION ${INC_DEST_DIR})

install(
    TARGETS yuneta-tls
    PERMISSIONS
    OWNER_READ OWNER_WRITE
    GROUP_READ GROUP_WRITE
    WORLD_READ
    DESTINATION ${LIB_DEST_DIR}
)

##############################################
#   sub-projects
##############################################
# TODO mueve los test fuera del core
# add_subdirectory(tests) # WARNING Si falta alguna funcion, el core no compila, por la dependencia de tests
