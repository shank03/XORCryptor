#
# Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#

cmake_minimum_required(VERSION 3.23)

project(XORCryptorCLI)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -std=c++17 -O3 -D_GLIBCXX_ASSERTIONS")

add_executable(XORCryptorCLI main.cpp cli.h cli.cpp xor_cryptor.h xor_cryptor.cpp)
target_link_libraries(XORCryptorCLI pthread)
