cmake_minimum_required(VERSION 2.8)
project(SSL_test C)

set(CMAKE_C_STANDARD 99)

#include_directories("/Users/liuwei/Applications/tassl/include")
#link_directories("/Users/liuwei/Applications/tassl/lib")

#include_directories("/Users/liuwei/Applications/tassl-sdf/include")
#link_directories("/Users/liuwei/Applications/tassl-sdf/lib")

# include_directories("/Users/liuwei/Applications/tongsuo/include")
# link_directories("/Users/liuwei/Applications/tongsuo/lib")

include_directories("/opt/tongsuo/include")
link_directories("/opt/tongsuo/lib64")

#include_directories("/usr/local/lib")
#link_directories("/usr/local/include")

#add_executable(SSL_test main.c)
#target_link_libraries(SSL_test ssl crypto dl pthread)

add_executable(server server.c tun.c)
target_link_libraries(server ssl crypto dl pthread)
# target_link_libraries(server gmssl crypto dl pthread)

add_executable(client client.c tun.c)
target_link_libraries(client ssl crypto dl pthread)
#target_link_libraries(client gmssl crypto dl pthread)