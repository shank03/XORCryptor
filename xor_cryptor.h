/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

#ifndef XOR_CRYPTOR_H
#define XOR_CRYPTOR_H

#include <vector>
#include <fstream>
#include <filesystem>
#include "cli.h"

class XorCrypt {

    typedef unsigned char bit;

    struct CipherData;

    struct ByteOrderInfo;

    struct BitStream;

    struct Node;

    struct Byte;

    static void write_node_property(std::vector<bit> *stream, bit parent, uint64_t value);

    static void insert_node(std::vector<Byte *> *st, std::vector<bit> *exceptions, bit parent, Node *node);

    static Byte *get_next_valid_parent(std::vector<Byte *> *unique_byte_set, Byte *pByte, bit next_parent);

    static CipherData *encrypt_bytes(std::vector<bit> *input, uint64_t length, std::vector<bit> *key, CLIProgressIndicator *cli_interface);

    static CipherData *decrypt_bytes(std::vector<bit> *input, uint64_t length, std::vector<bit> *key, CLIProgressIndicator *cli_interface);

    static bool process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface);

    static CipherData *process_string(std::string &str, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface);

public:
    static CipherData *encrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface);

    static bool encrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface);

    static CipherData *decrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface);

    static bool decrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface);
};

#endif //XOR_CRYPTOR_H
