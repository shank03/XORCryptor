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
#include <iostream>
#include "cli.h"

struct XorCrypt {

    typedef unsigned char bit;

private:
    struct CipherData {
        std::vector<bit> data;
        bool error;

        explicit CipherData() : data(), error(false) {}

        explicit CipherData(bool er) : data(), error(er) {}

        void extract_string(std::string *dest) const {
            for (auto i: data) dest->push_back(reinterpret_cast<char &>(i));
        }
    };

    struct BitStream {
        int byte_length;
        std::vector<uint64_t> *bit_stream;

        BitStream() : byte_length(0), bit_stream(new std::vector<uint64_t>(8)) {}

        void to_bit_stream(uint64_t value) {
            if (value == 0) {
                byte_length = 1;
                std::fill(bit_stream->begin(), bit_stream->end(), 0);
                return;
            }

            std::fill(bit_stream->begin(), bit_stream->end(), value);
            int i;
            for (i = 0; i < 8; i++) {
                int shift = (i + 1) * 8;
                (*bit_stream)[i] <<= (0x40 - shift);
                (*bit_stream)[i] >>= 0x38;
            }
            for (i = 7; i >= 0 && (*bit_stream)[i] == 0;) i--;
            byte_length = i + 1;
        }

        void write_to_stream(std::vector<bit> *stream) const {
            for (int i = byte_length - 1; i >= 0; i--) stream->push_back((*bit_stream)[i]);
            std::fill(bit_stream->begin(), bit_stream->end(), 0);
        }

        ~BitStream() {
            delete bit_stream;
        }
    };

    struct Node;

    struct Byte {
        bit val;
        uint64_t idx, size, exp_idx;
        std::vector<bit> *stream;
        std::vector<uint64_t> *exceptions;

        explicit Byte(int val) : val(val), idx(0), size(0), exp_idx(0),
                                 stream(new std::vector<bit>()), exceptions(nullptr) {}

        ~Byte() {
            delete stream;
            delete exceptions;
        }
    };

    struct Node {
        bit val;
        Byte *next;

        Node() : val(0), next(nullptr) {}

        void reset() {
            val = 0;
            next = nullptr;
        }
    };

    void write_node_property(std::vector<bit> *stream, bit parent, uint64_t value) const;

    void insert_node(std::vector<Byte *> *unique_byte_set, std::vector<bit> *exceptions, bit parent, Node *node) const;

    CipherData *encrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len, CLIProgressIndicator *cli_interface) const;

    CipherData *decrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len, CLIProgressIndicator *cli_interface) const;

    bool process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface);

    CipherData *process_string(std::string &str, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface);

public:
    BitStream *mBitStream;
    std::vector<Byte *> *mByteSets;

    XorCrypt() {
        mBitStream = new BitStream();
        mByteSets = new std::vector<Byte *>(0xFF, nullptr);
        for (bit i = 0; i < 0xFF; i++) (*mByteSets)[i] = new Byte(i);
    }

    CipherData *encrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface);

    bool encrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface);

    CipherData *decrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface);

    bool decrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface);

    ~XorCrypt() {
        delete mByteSets;
        delete mBitStream;
    }
};

#endif //XOR_CRYPTOR_H
