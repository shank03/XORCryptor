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

struct XorCrypt {

    typedef unsigned char bit;

    struct StatusListener {
        virtual void print_status(const std::string &status) = 0;

        virtual void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) = 0;

        virtual ~StatusListener() = 0;
    };

private:
    StatusListener *mStatusListener = nullptr;

    struct CipherData {
        std::vector<bit> *data;
        bool error;

        explicit CipherData() : data(new std::vector<bit>()), error(false) {}

        explicit CipherData(bool er) : data(nullptr), error(er) {}

        void extract_string(std::string *dest) const {
            if (data == nullptr) return;
            for (auto i: *data) dest->push_back(reinterpret_cast<char &>(i));
            delete data;
        }
    };

    struct BitStream {
        int byte_length;
        uint64_t *bit_stream;

        BitStream() : byte_length(0), bit_stream(nullptr) {}

        void to_bit_stream(uint64_t value) {
            if (bit_stream == nullptr) bit_stream = (uint64_t *) malloc(8 * sizeof(uint64_t));

            if (value == 0) {
                byte_length = 1;
                std::fill(bit_stream, bit_stream + 8, 0);
                return;
            }

            std::fill(bit_stream, bit_stream + 8, value);
            int i;
            for (i = 0; i < 8; i++) {
                bit_stream[i] >>= uint64_t(i * 8);
                bit_stream[i] &= uint64_t(0xFF);
            }
            for (i = 7; i >= 0 && bit_stream[i] == 0;) i--;
            byte_length = i + 1;
        }

        void write_to_stream(std::vector<bit> *stream) const {
            for (int i = byte_length - 1; i >= 0; i--) stream->push_back(bit_stream[i]);
            std::fill(bit_stream, bit_stream + 8, 0);
        }

        ~BitStream() { free(bit_stream); }
    };

    struct Node;

    struct Byte {
        bit val;
        uint64_t idx, size;
        std::vector<bit> *stream;

        explicit Byte(int val) : val(val), idx(0), size(0), stream(new std::vector<bit>()) {}

        ~Byte() { delete stream; }
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

    BitStream *mBitStream;
    Byte **mByteSets;

    void write_node_property(std::vector<bit> *stream, bit parent, uint64_t value) const;

    static void insert_node(Byte **unique_byte_set, std::vector<bit> *exception_stream, bit parent, Node *node, uint64_t &idx);

    void e_map_bytes(const bit *input, uint64_t length, std::vector<bit> *exception_stream,
                     Byte **unique_byte_set, std::vector<bit> *byte_order, uint64_t *itr) const;

    template<typename Iterator>
    void process_stream(std::vector<bit> *ostream, Iterator begin, Iterator end, const bit *key, uint64_t *k_idx, uint64_t k_len) const;

    void e_flush_streams(const bit *key, uint64_t k_len, CipherData *pCipherData,
                         Byte **unique_byte_set, const std::vector<bit> *byte_order, uint64_t *itr) const;

    CipherData *encrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len) const;

    void d_parse_header(const bit *input, uint64_t length, const bit *key, uint64_t k_len, std::vector<bit> *exception_stream,
                        Byte **unique_byte_set, std::vector<bit> *byte_order, uint64_t *idx, uint64_t *progress) const;

    void d_flush_stream(uint64_t length, XorCrypt::CipherData *pCipherData, std::vector<bit> *exception_stream,
                        Byte **unique_byte_set, const std::vector<bit> *byte_order, uint64_t *progress) const;

    CipherData *decrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len) const;

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt);

    CipherData *process_string(const std::string &str, const std::string &key, bool to_encrypt);

    void print_status(const std::string &status) const {
        if (mStatusListener == nullptr) return;
        mStatusListener->print_status(status);
    }

    void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) const {
        if (mStatusListener == nullptr) return;
        mStatusListener->catch_progress(status, progress_ptr, total);
    }

    void print_speed(uint64_t fileSize, uint64_t time_end);

    void reset_bytes() {
        delete mBitStream;
        free(mByteSets);

        mBitStream = new BitStream();
        mByteSets = (Byte **) malloc(0x80);
        for (bit i = 0; i < 0x10; i++) mByteSets[i] = new Byte(i);
    }

public:
    XorCrypt() : mStatusListener(nullptr), mBitStream(nullptr), mByteSets(nullptr) {}

    CipherData *encrypt_string(const std::string &str, const std::string &key, StatusListener *listener = nullptr);

    bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener = nullptr);

    CipherData *decrypt_string(const std::string &str, const std::string &key, StatusListener *listener = nullptr);

    bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener = nullptr);

    ~XorCrypt() {
        delete mByteSets;
        delete mBitStream;
        delete mStatusListener;
    }
};

#endif //XOR_CRYPTOR_H
