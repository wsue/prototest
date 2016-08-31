cmake_minimum_required (VERSION 3.0)
project (quiccli)
set(CMAKE_C_FLAGS "-g")
set(CMAKE_LD_FLAGS "-lpthread")

include_directories(.)

set(LIBS pthread dl  ssl crypto  )

set(CMAKE_CXX_FLAGS "-O2 -std=gnu++11 -DSSLPROTOTEST -Wall -fpic -m64 -funroll-loops -mfpmath=sse -msse4 -march=native ")
add_executable(sslcli client.cpp ssltest.cpp test_helper.cpp)
add_executable(sslsvr server.cpp ssltest.cpp test_helper.cpp)
target_link_libraries(sslcli ${LIBS} )
target_link_libraries(sslsvr ${LIBS} )
