cmake_minimum_required(VERSION 2.8)
project(SSL_test C)

set(CMAKE_C_STANDARD 99)

include_directories("/opt/tongsuo/include")
link_directories("/opt/tongsuo/lib64")

add_executable(ssl-test main.c)
target_link_libraries(ssl-test ssl crypto)

add_executable(server server.c protocol.c tun.c)
target_link_libraries(server ssl crypto dl pthread)

add_executable(client client.c protocol.c tun.c)
target_link_libraries(client ssl crypto dl pthread)

# 拷贝文件夹到指定的目录
add_custom_target(
  copy_certs ALL
  VERBATIM
  # COMMAND_EXPAND_LISTS
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/cert" "cert")
