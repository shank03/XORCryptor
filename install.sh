#!/bin/bash

cmake --no-warn-unused-cli -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
    -DCMAKE_BUILD_TYPE:STRING=Release -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/gcc \
    -DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/g++ -S. -Bbuild -G Ninja &&
    cmake --build "build" --config Release --target clean -j 10 && cmake --build "build" --config Release --target install -j 10
