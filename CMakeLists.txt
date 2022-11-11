cmake_minimum_required(VERSION 3.23)
project(XORCryptor)

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
    XORCryptor main.cpp
    cli.cpp cli.h
    hmac_sha256.cpp hmac_sha256.h
    xor_cryptor.cpp xor_cryptor.h
)

install(TARGETS XORCryptor DESTINATION bin)
install(FILES README.md DESTINATION .)
