cmake_minimum_required(VERSION 3.13)

project(CryptographicLibrary)

file(GLOB SOURCE src/* include/${PROJECT_NAME}/*)
add_library(${PROJECT_NAME} ${SOURCE})

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_subdirectory(submodule)

if (${TEST})
    find_package(GTest)
    file(GLOB SOURCE_TEST test/* src/* include/${PROJECT_NAME}/* )
    add_executable(Test${PROJECT_NAME}  ${SOURCE_TEST})
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DTEST_ASSERT")
    target_link_libraries(Test${PROJECT_NAME}
            GTest::GTest
            BaseTools::tools
    )
endif ()


#execute_process(COMMAND git describe --tags --always WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE GIT_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
#execute_process(COMMAND ${CMAKE_COMMAND} -E env TZ=UTC git log -1 --format=%cd --date=format-local:"%d.%m.%Y %H:%M:%S" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE GIT_SOURCE_DATE OUTPUT_STRIP_TRAILING_WHITESPACE)
#string(TIMESTAMP PROJECT_BUILD_DATE "%d.%m.%Y %H:%M:%S" UTC)
#add_definitions(-DPROJECT_NAME="${PROJECT_NAME}" -DPROJECT_VERSION="${GIT_VERSION}" -DPROJECT_SOURCE_DATE=${GIT_SOURCE_DATE} -DPROJECT_BUILD_DATE="${PROJECT_BUILD_DATE}")
