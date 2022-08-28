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
#include <map>
#include <fstream>

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

    inline static std::vector<bit> *gInput = nullptr, *gKey = nullptr;
    inline static uint64_t gLen = 0;

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
    };

    struct Node;

    struct Byte {
        bit val;
        uint64_t size, idx;
        std::vector<Node *> nodes;

        explicit Byte(int val) : val(val), idx(0), size(0) {}
    };

    struct Node {
        bit val;
        Byte *next;

        Node(bit v, Byte *n) : val(v), next(n) {}
    };

    static void write_node_size(std::vector<bit> *stream, bit parent, uint64_t value) {
        auto *bs = new ByteStream(value);
        parent = (parent << 4) | reinterpret_cast<bit &>(bs->byte_length);

        stream->push_back(parent);
        bs->write_to_stream(stream);
    }

    static void insert_unique_parent(std::vector<Byte *> *st, Byte *byte) {
        for (Byte *b: *st) {
            if (b->val == byte->val) return;
        }
        st->push_back(byte);
    }

    static CipherData *encrypt_bytes() {
        try {
            auto pCipherData = new CipherData();
            uint64_t ki = 0;

            std::map<bit, Byte *> mp;
            std::map<bit, std::vector<bit>> dump;

            std::vector<Byte *> st;
            std::vector<bit> stream, exceptions;

            bit prev_parent = UCHAR_MAX;
            Node *prev_node = nullptr;

            for (uint64_t i = 0; i < gLen; i++) {
                bit parent = (*gInput)[i], data = (*gInput)[i];
                parent >>= 4;
                data <<= 4;
                data >>= 4;

                Byte *byte = mp.find(parent) != mp.end() ? mp[parent] : mp[parent] = new Byte(parent);
                Node *node = new Node(data, nullptr);
                byte->nodes.emplace_back(node);
                byte->size = byte->nodes.size();

                if (prev_node != nullptr && prev_parent != UCHAR_MAX && prev_parent != parent) {
                    prev_node->next = mp[parent];
                }
                prev_parent = parent;
                prev_node = node;
                insert_unique_parent(&st, byte);
            }

            pCipherData->data.push_back(static_cast<bit>(mp.size()));
            for (auto &pByte: st) {
                write_node_size(&pCipherData->data, pByte->val, pByte->size);

                while (pByte->idx < pByte->size) {
                    Node *node = pByte->nodes[pByte->idx];
                    bit data = node->val;
                    data <<= 4;

                    if (node->next) {
                        bit parent = node->next->val;
                        if (parent == 0) write_node_size(&exceptions, pByte->val, pByte->idx);
                        data |= parent;
                    }
                    pByte->idx++;

                    if (ki == gKey->size()) ki = 0;
                    data ^= (*gKey)[ki++];
                    stream.push_back(data);
                }
            }
            stream.insert(stream.end(), exceptions.begin(), exceptions.end());
            pCipherData->data.insert(pCipherData->data.end(), stream.begin(), stream.end());
            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static CipherData *decrypt_bytes() {
        try {
            uint64_t ki = 0;
            auto pCipherData = new CipherData();

            std::map<bit, Byte *> mp;
            std::vector<Byte *> st;
            for (int i = 0; i < 16; i++) mp[i] = nullptr;

            auto *pBof = new ByteOrderInfo();
            uint64_t idx = 0;
            bit token_len = (*gInput)[idx++];
            while (token_len--) {
                pBof->extract_order((*gInput)[idx++]);
                bit parent = pBof->l, b_len = pBof->r;

                uint64_t data_len = 0, bits = idx + uint64_t(b_len);
                while (idx < bits) {
                    data_len <<= 8;
                    data_len |= uint64_t((*gInput)[idx++]);
                }
                mp[parent] = new Byte(parent);
                mp[parent]->size = data_len;
                st.push_back(mp[parent]);
            }

            for (auto &pByte: st) {
                while (pByte->nodes.size() != pByte->size) {
                    bit data = (*gInput)[idx++];
                    if (ki == (*gKey).size()) ki = 0;
                    data ^= (*gKey)[ki++];

                    pBof->extract_order(data);
                    bit val = pBof->l, next_parent = pBof->r;

                    pByte->nodes.push_back(new Node(val, next_parent == 0 ? nullptr : mp[next_parent]));
                }
            }

            while (idx < gLen) {
                pBof->extract_order((*gInput)[idx++]);
                bit parent = pBof->l;
                uint64_t bits = uint64_t(pBof->r) + idx;

                uint64_t node_idx = 0;
                while (idx < bits) {
                    node_idx <<= 8;
                    node_idx |= (*gInput)[idx++];
                }
                mp[parent]->nodes[node_idx]->next = mp[bit(0)];
            }

            Byte *curr = st[0];
            while (curr->idx < curr->size) {
                Node *node = curr->nodes[curr->idx++];

                bit data = curr->val << 4;
                data |= node->val;

                pCipherData->data.push_back(data);
                if (node->next) curr = node->next;
            }
            return pCipherData;
        } catch (std::exception &e) {
            return new CipherData(true);
        }
    }

    static bool process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt) {
        clearG();

        std::ifstream file(src_path, std::ios::binary);
        std::ofstream output_file(dest_path, std::ios::binary);
        if (!file.is_open()) return false;
        if (!output_file.is_open()) return false;

        gInput = new std::vector<bit>(), gKey = new std::vector<bit>();
        for (auto &i: key) gKey->push_back(reinterpret_cast<bit &>(i));
        while (!file.eof()) {
            char chr;
            file.get(chr);
            gInput->push_back(reinterpret_cast<bit &>(chr));
        }
        file.close();
        gLen = gInput->size();

        CipherData *res = to_encrypt ? encrypt_bytes() : decrypt_bytes();
        if (res->error) return false;
        for (auto &i: res->data) {
            output_file.put(reinterpret_cast<char &>(i));
        }
        output_file.close();
        delete res;
        return !file.is_open() && !output_file.is_open();
    }

    static CipherData *process_string(std::string &str, std::string &key, bool to_encrypt) {
        clearG();

        gInput = new std::vector<bit>(), gKey = new std::vector<bit>();
        for (auto &i: str) gInput->push_back(reinterpret_cast<bit &>(i));
        for (auto &i: key) gKey->push_back(reinterpret_cast<bit &>(i));
        gLen = gInput->size();
        return to_encrypt ? encrypt_bytes() : decrypt_bytes();
    }

    static void clearG() {
        if (gInput != nullptr) gInput->clear();
        gInput = nullptr;
        if (gKey != nullptr) gKey->clear();
        gKey = nullptr;
        gLen = 0;
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
