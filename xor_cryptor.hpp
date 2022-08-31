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

#include <vector>
#include <fstream>
#include <filesystem>

#pragma once

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 22-Aug-2022
 */
class XorCrypt {

    typedef unsigned char bit;

    typedef std::function<void(std::string stat, bool print)> ProcessCallBack;

    struct CipherData {
        std::vector<bit> data;
        bool error;

        explicit CipherData() : data(), error(false) {}

        explicit CipherData(bool er) : data(), error(er) {}

        void extract_string(std::string *dest) const {
            for (auto i: data) dest->push_back(reinterpret_cast<char &>(i));
        }
    };

    struct ByteOrderInfo {
        bit lv, rv;

        ByteOrderInfo() : lv(0), rv(0) {}

        void extract_order(bit value) {
            lv = value >> 4, rv = value << 4;
            rv >>= 4;
        }

        ~ByteOrderInfo() = default;
    };

    struct BitStream {
        int byte_length;
        std::vector<uint64_t> *bit_stream;

        explicit BitStream(uint64_t value) : byte_length(0), bit_stream(nullptr) {
            if (value == 0) {
                byte_length = 1;
                bit_stream = new std::vector<uint64_t>(2, 0);
                return;
            }

            bit_stream = new std::vector<uint64_t>(8, value);
            int i;
            for (i = 0; i < 8; i++) {
                int shift = (i + 1) * 8;
                (*bit_stream)[i] <<= (64 - shift);
                (*bit_stream)[i] >>= 56;
            }
            for (i = 7; i >= 0 && (*bit_stream)[i] == 0;) i--;
            byte_length = i + 1;
        }

        void write_to_stream(std::vector<bit> *stream) const {
            for (int i = byte_length - 1; i >= 0; i--) stream->push_back((*bit_stream)[i]);
        }

        ~BitStream() {
            delete bit_stream;
        }
    };

    struct Node;

    struct Byte {
        bit val;
        uint64_t size, idx, exp_idx;
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

    static void write_node_property(std::vector<bit> *stream, bit parent, uint64_t value) {
        auto *pBS = new BitStream(value);
        parent = (parent << 4) | reinterpret_cast<bit &>(pBS->byte_length);

        stream->push_back(parent);
        pBS->write_to_stream(stream);
        delete pBS;
    }

    static void insert_node(std::vector<Byte *> *st, std::vector<bit> *exceptions, bit parent, Node *node) {
        bit data = node->val;
        data <<= 4;
        if (node->next) {
            bit next_parent = node->next->val;
            if (next_parent == 0) write_node_property(exceptions, parent, (*st)[parent]->idx);
            data |= next_parent;
        }
        (*st)[parent]->idx++;
        (*st)[parent]->stream->push_back(data);
    }

    static Byte *get_next_valid_parent(std::vector<Byte *> *unique_byte_set, Byte *pByte, bit next_parent) {
        if (next_parent == 0) {
            if (pByte->exceptions == nullptr || pByte->exp_idx >= pByte->exceptions->size()) return pByte;
            uint64_t exp_idx = (*pByte->exceptions)[pByte->exp_idx];
            if (pByte->idx - uint64_t(1) == exp_idx) {
                pByte->exp_idx++;
                return (*unique_byte_set)[next_parent];
            } else {
                return pByte;
            }
        }
        return (*unique_byte_set)[next_parent];
    }

    static CipherData *encrypt_bytes(std::vector<bit> *input, uint64_t length, std::vector<bit> *key, ProcessCallBack *callBack) {
        try {
            (*callBack)("Started encryption", false);
            auto pCipherData = new CipherData();
            uint64_t k_idx = 0;

            auto *unique_byte_set = new std::vector<Byte *>(16, nullptr);
            auto *stream = new std::vector<bit>(), *exceptions = new std::vector<bit>, *byte_order = new std::vector<bit>();

            Node *pNode = new Node();
            for (uint64_t i = 0; i < length; i++) {
                pNode->reset();
                bit parent = (*input)[i] >> 4, data = (*input)[i] << 4;
                data >>= 4;

                if ((*unique_byte_set)[parent] == nullptr) {
                    (*unique_byte_set)[parent] = new Byte(parent);
                    byte_order->push_back(parent);
                }
                pNode->val = data;
                (*unique_byte_set)[parent]->size++;

                if (i != length - 1) {
                    bit next_parent = (*input)[i + 1] >> 4;
                    if ((*unique_byte_set)[next_parent] == nullptr) {
                        (*unique_byte_set)[next_parent] = new Byte(next_parent);
                        byte_order->push_back(next_parent);
                    }
                    if (parent != next_parent) pNode->next = (*unique_byte_set)[next_parent];
                }
                insert_node(unique_byte_set, exceptions, parent, pNode);
            }

            (*callBack)("Flushing byte stream", false);
            pCipherData->data.push_back(static_cast<bit>(byte_order->size()));
            for (auto &i: *byte_order) {
                Byte *pByte = (*unique_byte_set)[i];
                write_node_property(&pCipherData->data, pByte->val, pByte->size);

                for (auto &b: *pByte->stream) {
                    if (k_idx == key->size()) k_idx = 0;
                    bit bData = b;
                    bData ^= (*key)[k_idx++];
                    stream->push_back(bData);
                }
                delete pByte->stream;
            }
            delete unique_byte_set;
            pCipherData->data.insert(pCipherData->data.end(), stream->begin(), stream->end());
            pCipherData->data.insert(pCipherData->data.end(), exceptions->begin(), exceptions->end());
            delete byte_order;
            delete stream;
            delete exceptions;

            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static CipherData *decrypt_bytes(std::vector<bit> *input, uint64_t length, std::vector<bit> *key, ProcessCallBack *callBack) {
        try {
            (*callBack)("Started decryption", false);
            uint64_t k_idx = 0;
            auto pCipherData = new CipherData();

            auto *unique_byte_set = new std::vector<Byte *>(16, nullptr);
            auto *byte_order = new std::vector<bit>();
            auto *pBOF = new ByteOrderInfo();

            uint64_t idx = 0, exception_partition = 0;
            bit parent_length = (*input)[idx++];
            while (parent_length--) {
                pBOF->extract_order((*input)[idx++]);
                bit parent = pBOF->lv, bits_length = pBOF->rv;

                uint64_t child_count = 0, bits_idx = idx + uint64_t(bits_length);
                while (idx < bits_idx) {
                    child_count <<= 8;
                    child_count |= uint64_t((*input)[idx++]);
                }
                if ((*unique_byte_set)[parent] == nullptr) {
                    (*unique_byte_set)[parent] = new Byte(parent);
                    byte_order->push_back(parent);
                }
                (*unique_byte_set)[parent]->size = child_count;
                exception_partition += child_count;
            }
            uint64_t t_idx = idx;
            idx += exception_partition;

            while (idx < length) {
                pBOF->extract_order((*input)[idx++]);
                bit parent = pBOF->lv;
                uint64_t bits = uint64_t(pBOF->rv) + idx;

                uint64_t node_idx = 0;
                while (idx < bits) {
                    node_idx <<= 8;
                    node_idx |= (*input)[idx++];
                }
                if ((*unique_byte_set)[parent]->exceptions == nullptr) {
                    (*unique_byte_set)[parent]->exceptions = new std::vector<uint64_t>();
                }
                (*unique_byte_set)[parent]->exceptions->push_back(node_idx);
            }
            idx = t_idx;
            (*callBack)("Parsed header", false);

            for (auto &i: *byte_order) {
                while ((*unique_byte_set)[i]->stream->size() != (*unique_byte_set)[i]->size) {
                    bit data = (*input)[idx++];
                    if (k_idx == key->size()) k_idx = 0;
                    data ^= (*key)[k_idx++];
                    (*unique_byte_set)[i]->stream->push_back(data);
                }
            }

            (*callBack)("Flushing byte stream", false);
            Byte *pByte = (*unique_byte_set)[(*byte_order)[0]];
            while (pByte->idx < pByte->size) {
                bit data = (*pByte->stream)[pByte->idx++];

                pBOF->extract_order(data);
                bit val = pBOF->lv, next_parent = pBOF->rv;
                data = pByte->val << 4;
                data |= val;

                pCipherData->data.push_back(data);
                pByte = get_next_valid_parent(unique_byte_set, pByte, next_parent);
            }
            delete pBOF;
            delete unique_byte_set;
            delete byte_order;
            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static bool process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt, ProcessCallBack *callBack) {
        std::ifstream file(src_path, std::ios::binary);
        std::ofstream output_file(dest_path, std::ios::binary);
        if (!file.is_open()) return false;
        if (!output_file.is_open()) return false;
        (*callBack)("Reading file", false);

        auto *cipher_key = new std::vector<bit>();
        for (auto &i: key) cipher_key->push_back(reinterpret_cast<bit &>(i));

        auto *input = new std::vector<char>();
        input->reserve(std::filesystem::file_size(src_path));
        input->assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        (*callBack)("Size: " + std::to_string(input->size()) + " bytes", true);

        CipherData *res = to_encrypt ?
                          encrypt_bytes(reinterpret_cast<std::vector<bit> *>(input), input->size(), cipher_key, callBack) :
                          decrypt_bytes(reinterpret_cast<std::vector<bit> *>(input), input->size(), cipher_key, callBack);
        delete input;

        if (res->error) return false;
        (*callBack)("Writing file", false);
        for (auto &i: res->data) {
            output_file.put(reinterpret_cast<char &>(i));
        }
        delete res;
        output_file.close();
        return !file.is_open() && !output_file.is_open();
    }

    static CipherData *process_string(std::string &str, std::string &key, bool to_encrypt, ProcessCallBack *callBack) {
        auto *input = new std::vector<bit>(), *cipher_key = new std::vector<bit>();
        for (auto &i: str) input->push_back(reinterpret_cast<bit &>(i));
        for (auto &i: key) cipher_key->push_back(reinterpret_cast<bit &>(i));
        return to_encrypt ?
               encrypt_bytes(input, input->size(), cipher_key, callBack) :
               decrypt_bytes(input, input->size(), cipher_key, callBack);
    }

public:
    static CipherData *encrypt_string(std::string &str, std::string &key, ProcessCallBack *callBack) {
        return process_string(str, key, true, callBack);
    }

    static bool encrypt_file(std::string &src_path, std::string &dest_path, std::string &key, ProcessCallBack *callBack) {
        return process_file(src_path, dest_path, key, true, callBack);
    }

    static CipherData *decrypt_string(std::string &str, std::string &key, ProcessCallBack *callBack) {
        return process_string(str, key, false, callBack);
    }

    static bool decrypt_file(std::string &src_path, std::string &dest_path, std::string &key, ProcessCallBack *callBack) {
        return process_file(src_path, dest_path, key, false, callBack);
    }
};
