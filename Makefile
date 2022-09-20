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

CC := g++
CFLAGS := -Wall -Wextra -Werror -std=c++17 -O3 -D_GLIBCXX_ASSERTIONS
LIB := -pthread -pedantic
INC := -I.

BIN_DIR := $(CURDIR)/bin
BUILD_DIR := $(CURDIR)/build
TARGET := $(BIN_DIR)/xor_cryptor

IS_WIN := false
ifeq ($(OS),Windows_NT)
	TARGET := $(BIN_DIR)/xor_cryptor.exe
	IS_WIN := true
endif

all: $(TARGET)

ifeq ($(IS_WIN),false)
install: all
	@echo "Installing"; sudo cp $(TARGET) /usr/bin

uninstall:
	sudo rm -rf /usr/bin/xor_cryptor
endif

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/cli.o $(BUILD_DIR)/xor_cryptor.o $(BUILD_DIR)/xor_cryptor_lite.o
	$(shell if [ ! -d "$(BIN_DIR)" ]; then\
	    mkdir "$(BIN_DIR)";\
	fi)
	$(CC) $^ -o $(TARGET) $(LIB)

$(BUILD_DIR)/%.o: %.cpp
	$(shell if [ ! -d "$(BUILD_DIR)" ]; then\
    	mkdir "$(BUILD_DIR)";\
    fi)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(BUILD_DIR)/xor_cryptor.o: xor_cryptor.cpp xor_cryptor.h
$(BUILD_DIR)/xor_cryptor_lite.o: xor_cryptor_lite.cpp xor_cryptor_lite.h
$(BUILD_DIR)/cli.o: cli.cpp cli.h
$(BUILD_DIR)/main.o: main.cpp

clean:
	rm -rf $(BUILD_DIR)/*.o $(TARGET)
