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
        bit l, r;

        ByteOrderInfo() : l(0), r(0) {}

        void extract_order(bit value) {
            l = value >> 4, r = value << 4;
            r >>= 4;
        }

        ~ByteOrderInfo() = default;
    };

    struct ByteStream {
        int byte_length;
        std::vector<uint64_t> *bit_stream;

        explicit ByteStream(uint64_t value) : byte_length(0), bit_stream(nullptr) {
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

        ~ByteStream() {
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

    static void write_node_size(std::vector<bit> *stream, bit parent, uint64_t value) {
        auto *bs = new ByteStream(value);
        parent = (parent << 4) | reinterpret_cast<bit &>(bs->byte_length);

        stream->push_back(parent);
        bs->write_to_stream(stream);
        delete bs;
    }

    static void write_node(std::vector<Byte *> *st, std::vector<bit> *exceptions, bit parent, Node *node) {
        bit bData = node->val;
        bData <<= 4;
        if (node->next) {
            bit bParent = node->next->val;
            if (bParent == 0) write_node_size(exceptions, parent, (*st)[parent]->idx);
            bData |= bParent;
        }
        (*st)[parent]->idx++;
        (*st)[parent]->stream->push_back(bData);
    }

    static CipherData *encrypt_bytes(std::vector<bit> *input, uint64_t i_len, std::vector<bit> *key) {
        try {
            auto pCipherData = new CipherData();
            uint64_t k_idx = 0;

            auto *st = new std::vector<Byte *>(16, nullptr);
            auto *stream = new std::vector<bit>(), *exceptions = new std::vector<bit>,
                    *order = new std::vector<bit>();

            Node *node = new Node();
            for (uint64_t i = 0; i < i_len; i++) {
                node->reset();
                bit parent = (*input)[i] >> 4, data = (*input)[i] << 4;
                data >>= 4;

                if ((*st)[parent] == nullptr) {
                    (*st)[parent] = new Byte(parent);
                    order->push_back(parent);
                }
                node->val = data;
                (*st)[parent]->size++;

                if (i != i_len - 1) {
                    bit next_parent = (*input)[i + 1] >> 4;
                    if ((*st)[next_parent] == nullptr) {
                        (*st)[next_parent] = new Byte(next_parent);
                        order->push_back(next_parent);
                    }
                    if (parent != next_parent) node->next = (*st)[next_parent];
                }
                write_node(st, exceptions, parent, node);
            }

            pCipherData->data.push_back(static_cast<bit>(order->size()));
            for (auto &i: *order) {
                Byte *pByte = (*st)[i];
                write_node_size(&pCipherData->data, pByte->val, pByte->size);

                for (auto &b: *pByte->stream) {
                    if (k_idx == key->size()) k_idx = 0;
                    bit bData = b;
                    bData ^= (*key)[k_idx++];
                    stream->push_back(bData);
                }
                delete pByte->stream;
            }
            delete st;
            pCipherData->data.insert(pCipherData->data.end(), stream->begin(), stream->end());
            pCipherData->data.insert(pCipherData->data.end(), exceptions->begin(), exceptions->end());
            delete order;
            delete stream;
            delete exceptions;

            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static CipherData *decrypt_bytes(std::vector<bit> *input, uint64_t i_len, std::vector<bit> *key) {
        try {
            uint64_t ki = 0;
            auto pCipherData = new CipherData();

            auto *st = new std::vector<Byte *>(16, nullptr);
            auto *order = new std::vector<bit>();
            auto *pBOF = new ByteOrderInfo();

            uint64_t idx = 0, exception_partition = 0;
            bit parent_len = (*input)[idx++];
            while (parent_len--) {
                pBOF->extract_order((*input)[idx++]);
                bit parent = pBOF->l, b_len = pBOF->r;

                uint64_t data_len = 0, bits = idx + uint64_t(b_len);
                while (idx < bits) {
                    data_len <<= 8;
                    data_len |= uint64_t((*input)[idx++]);
                }
                if ((*st)[parent] == nullptr) {
                    (*st)[parent] = new Byte(parent);
                    order->push_back(parent);
                }
                (*st)[parent]->size = data_len;
                exception_partition += data_len;
            }
            uint64_t t_idx = idx;
            idx += exception_partition;

            while (idx < i_len) {
                pBOF->extract_order((*input)[idx++]);
                bit parent = pBOF->l;
                uint64_t bits = uint64_t(pBOF->r) + idx;

                uint64_t node_idx = 0;
                while (idx < bits) {
                    node_idx <<= 8;
                    node_idx |= (*input)[idx++];
                }
                if ((*st)[parent]->exceptions == nullptr) (*st)[parent]->exceptions = new std::vector<uint64_t>();
                (*st)[parent]->exceptions->push_back(node_idx);
            }
            idx = t_idx;

            for (auto &i: *order) {
                while ((*st)[i]->stream->size() != (*st)[i]->size) {
                    bit data = (*input)[idx++];
                    if (ki == key->size()) ki = 0;
                    data ^= (*key)[ki++];
                    (*st)[i]->stream->push_back(data);
                }
            }

            Byte *pByte = (*st)[(*order)[0]];
            while (pByte->idx < pByte->size) {
                bit data = (*pByte->stream)[pByte->idx++];

                pBOF->extract_order(data);
                bit val = pBOF->l, next_parent = pBOF->r;
                data = pByte->val << 4;
                data |= val;

                pCipherData->data.push_back(data);
                pByte = [&]() -> Byte * {
                    if (next_parent == 0) {
                        if (pByte->exceptions == nullptr || pByte->exp_idx >= pByte->exceptions->size()) return pByte;
                        uint64_t exp_idx = (*pByte->exceptions)[pByte->exp_idx];
                        if (pByte->idx - uint64_t(1) == exp_idx) {
                            pByte->exp_idx++;
                            return (*st)[next_parent];
                        } else {
                            return pByte;
                        }
                    }
                    return (*st)[next_parent];
                }();
            }
            delete pBOF;
            delete st;
            delete order;
            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static bool process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt) {
        std::ifstream file(src_path, std::ios::binary);
        std::ofstream output_file(dest_path, std::ios::binary);
        if (!file.is_open()) return false;
        if (!output_file.is_open()) return false;

        auto *cipher_key = new std::vector<bit>();
        for (auto &i: key) cipher_key->push_back(reinterpret_cast<bit &>(i));

        auto *input = new std::vector<char>();
        input->reserve(std::filesystem::file_size(src_path));
        input->assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        CipherData *res = to_encrypt ?
                          encrypt_bytes(reinterpret_cast<std::vector<bit> *>(input), input->size(), cipher_key) :
                          decrypt_bytes(reinterpret_cast<std::vector<bit> *>(input), input->size(), cipher_key);
        delete input;

        if (res->error) return false;
        for (auto &i: res->data) {
            output_file.put(reinterpret_cast<char &>(i));
        }
        delete res;
        output_file.close();
        return !file.is_open() && !output_file.is_open();
    }

    static CipherData *process_string(std::string &str, std::string &key, bool to_encrypt) {
        auto *input = new std::vector<bit>(), *cipher_key = new std::vector<bit>();
        for (auto &i: str) input->push_back(reinterpret_cast<bit &>(i));
        for (auto &i: key) cipher_key->push_back(reinterpret_cast<bit &>(i));
        return to_encrypt ?
               encrypt_bytes(input, input->size(), cipher_key) :
               decrypt_bytes(input, input->size(), cipher_key);
    }

public:
    static CipherData *encrypt_string(std::string &str, std::string &key) {
        return process_string(str, key, true);
    }

    static bool encrypt_file(std::string &src_path, std::string &dest_path, std::string &key) {
        return process_file(src_path, dest_path, key, true);
    }

    static CipherData *decrypt_string(std::string &str, std::string &key) {
        return process_string(str, key, false);
    }

    static bool decrypt_file(std::string &src_path, std::string &dest_path, std::string &key) {
        return process_file(src_path, dest_path, key, false);
    }
};
