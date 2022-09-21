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

#include "xor_cryptor_base.h"

class XorCryptor : private XorCryptor_Base {
private:
    struct CipherData {
        std::vector<byte> *data;
        bool error;

        explicit CipherData() : data(new std::vector<byte>()), error(false) {}

        explicit CipherData(bool er) : data(nullptr), error(er) {}

        void extract_string(std::string *dest) const {
            if (data == nullptr) return;
            for (auto i: *data) dest->push_back(reinterpret_cast<char &>(i));
            delete data;
        }
    };

    struct BitStream {
        int byte_length;
        byte64 *bit_stream;

        BitStream() : byte_length(0), bit_stream(nullptr) {}

        void to_bit_stream(byte64 value) {
            if (bit_stream == nullptr) bit_stream = new byte64[8];

            if (value == 0) {
                byte_length = 1;
                std::fill(bit_stream, bit_stream + 8, 0);
                return;
            }

            std::fill(bit_stream, bit_stream + 8, value);
            int i;
            for (i = 0; i < 8; i++) {
                bit_stream[i] >>= byte64(i * 8);
                bit_stream[i] &= byte64(0xFF);
            }
            for (i = 7; i >= 0 && bit_stream[i] == 0;) i--;
            byte_length = i + 1;
        }

        void write_to_stream(std::vector<byte> *stream) const {
            for (int i = byte_length - 1; i >= 0; i--) stream->push_back(bit_stream[i]);
            std::fill(bit_stream, bit_stream + 8, 0);
        }

        ~BitStream() { delete[] bit_stream; }
    };

    struct ByteNode {
        byte val;
        byte64 idx, size;
        ByteStream *byte_stream;

        explicit ByteNode(byte parent) : val(parent), idx(0), size(0), byte_stream(new ByteStream()) {}

        ~ByteNode() { delete byte_stream; }
    };

    struct Node {
        byte val;
        ByteNode *next;

        Node() : val(0), next(nullptr) {}

        ~Node() { delete next; }
    };

    BitStream *mBitStream;

    void write_node_property(ByteStream *stream, byte parent, byte64 value) const;

    static void insert_node(ByteNode *pByte, ByteStream *exception_stream, Node *pNode, byte64 &idx);

    template<typename OStream, typename Iterator>
    void process_stream(OStream *ostream, Iterator begin, Iterator end, const byte *cipher_key, byte64 *key_idx, byte64 key_length) const;

    void e_map_bytes(const byte *input_bytes, byte64 input_length, ByteStream *exception_stream,
                     ByteNode **unique_byte_set, ByteStream *byte_order, byte64 *itr) const;

    void e_flush_streams(const byte *cipher_key, byte64 key_length, CipherData *pCipherData,
                         ByteNode **unique_byte_set, const ByteStream *byte_order, byte64 *itr) const;

    CipherData *encrypt_bytes(const byte *input_bytes, byte64 input_length, const byte *cipher_key, byte64 key_length) const;

    void d_parse_header(const byte *input, byte64 length, const byte *key, byte64 k_len, ByteStream *exception_stream,
                        ByteNode **unique_byte_set, ByteStream *byte_order, byte64 *idx, byte64 *progress) const;

    void d_flush_stream(byte64 length, CipherData *pCipherData, ByteStream *exception_stream,
                        ByteNode **unique_byte_set, byte top, byte64 *progress) const;

    CipherData *decrypt_bytes(const byte *input_bytes, byte64 input_length, const byte *cipher_key, byte64 key_length) const;

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt);

    CipherData *process_string(const std::string &str, const std::string &key, bool to_encrypt);

public:
    inline static const std::string FILE_EXTENSION = ".xor";

    XorCryptor() {
        mStatusListener = nullptr;
        mBitStream = new BitStream();
    }

    CipherData *encrypt_string(const std::string &str, const std::string &key, StatusListener *listener = nullptr);

    bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    CipherData *decrypt_string(const std::string &str, const std::string &key, StatusListener *listener = nullptr);

    bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    ~XorCryptor() {
        delete mBitStream;
    }
};

#endif //XOR_CRYPTOR_H
