cmake_minimum_required(VERSION 2.8.9)
project(HIBEGS)

#However, the file(GLOB...) allows for wildcard additions:

file(GLOB SOURCES "test/test.cpp")
find_package(GTest REQUIRED)
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}
    /usr/local/include
    /usr/include
    include
)

# 需包含的库文件
link_directories(
    ${PROJECT_BINARY_DIR}/lib
    /usr/local/lib
    /usr/lib
)

add_subdirectory(src)
add_executable(HibeGS ${SOURCES})

TARGET_LINK_LIBRARIES(HibeGS src)
TARGET_LINK_LIBRARIES(HibeGS  gtest gtest_main relic)
TARGET_LINK_LIBRARIES(HibeGS ${CMAKE_THREAD_LIBS_INIT})



