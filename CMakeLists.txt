cmake_minimum_required(VERSION 3.23)
project(XORCryptorCLI)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options("$<$<CONFIG:RELEASE>:/O2>" "/arch:AVX512" "/Oi" "/fp:precise" "/sdl" "/GL")
else()
    add_compile_options("-Wall" "-Wextra" "-Werror" "$<$<CONFIG:RELEASE>:-O3>")

    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        add_compile_options("-stdlib=libc++")
    else()
        # nothing special for gcc at the moment
    endif()
endif()

add_executable(
    XORCryptorCLI
    main.cpp
    all.h
    cli.hpp
    task_pool.hpp
)

add_subdirectory(HMAC)
target_include_directories(XORCryptorCLI PUBLIC HMAC)
target_link_directories(XORCryptorCLI PRIVATE HMAC)
target_link_libraries(XORCryptorCLI HMAC_SHA256)

add_subdirectory(XRC)
target_include_directories(XORCryptorCLI PUBLIC XRC)
target_link_directories(XORCryptorCLI PRIVATE XRC)
target_link_libraries(XORCryptorCLI XORCryptorLib)

install(TARGETS XORCryptorCLI DESTINATION .)
install(FILES README.md DESTINATION .)
