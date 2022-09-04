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

#include "xor_cryptor.h"

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 22-Aug-2022
 */

void XorCrypt::extract_order(bit value, bit *lv, bit *rv) {
    (*lv) = value >> 4;
    (*rv) = value & 0x0F;
}

void XorCrypt::write_node_property(std::vector<bit> *stream, bit parent, uint64_t value) {
    mBitStream->to_bit_stream(value);
    parent = (parent << 4) | reinterpret_cast<bit &>(mBitStream->byte_length);

    stream->push_back(parent);
    mBitStream->write_to_stream(stream);
}

void XorCrypt::insert_node(std::vector<Byte *> *unique_byte_set, std::vector<bit> *exceptions, bit parent, Node *node) {
    bit data = (node->val << 4);
    if (node->next) {
        bit next_parent = node->next->val;
        if (next_parent == 0) write_node_property(exceptions, parent, (*unique_byte_set)[parent]->idx);
        data |= next_parent;
    }
    (*unique_byte_set)[parent]->idx++;
    (*unique_byte_set)[parent]->stream->push_back(data);
}

XorCrypt::CipherData *XorCrypt::encrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len, CLIProgressIndicator *cli_interface) {
    try {
        CLIProgressIndicator::print_status("Started encryption");
        auto pCipherData = new CipherData();
        uint64_t k_idx = 0;

        mBitStream = new BitStream();
        auto *unique_byte_set = new std::vector<Byte *>(0xFF, nullptr),
                *byte_sets = new std::vector<Byte *>(0xFF, nullptr);
        for (bit i = 0; i < 16; i++) (*byte_sets)[i] = new Byte(i);
        auto *exceptions = new std::vector<bit>, *byte_order = new std::vector<bit>();

        Node *pNode = new Node();
        cli_interface->set_status("Mapping bytes", length);
        uint64_t itr = 0;
        cli_interface->catch_progress(&itr);
        for (; itr < length; itr++) {
            pNode->reset();
            bit parent = 0, data = 0;
            extract_order(input[itr], &parent, &data);

            if ((*unique_byte_set)[parent] == nullptr) byte_order->push_back(parent);
            (*unique_byte_set)[parent] = (*byte_sets)[parent];
            pNode->val = data;
            (*unique_byte_set)[parent]->size++;

            if (itr != length - 1) {
                bit next_parent = input[itr + 1] >> 4;
                if ((*unique_byte_set)[next_parent] == nullptr) byte_order->push_back(next_parent);
                (*unique_byte_set)[next_parent] = (*byte_sets)[next_parent];
                if (parent != next_parent) pNode->next = (*unique_byte_set)[next_parent];
            }
            insert_node(unique_byte_set, exceptions, parent, pNode);
        }
        delete[] input;

        cli_interface->set_status("Flushing byte stream", byte_order->size());
        pCipherData->data.push_back(static_cast<bit>(byte_order->size()));
        for (auto &order: *byte_order) {
            Byte *pByte = (*unique_byte_set)[order];
            write_node_property(&pCipherData->data, pByte->val, pByte->size);
        }
        delete mBitStream;
        itr = 0;
        for (; itr < byte_order->size(); itr++) {
            Byte *pByte = (*unique_byte_set)[(*byte_order)[itr]];
            for (auto &b: *pByte->stream) {
                if (k_idx == k_len) k_idx = 0;
                bit bData = b;
                bData ^= key[k_idx++];
                pCipherData->data.push_back(bData);
            }
            delete pByte->stream;
        }
        delete unique_byte_set;
        pCipherData->data.insert(pCipherData->data.end(), exceptions->begin(), exceptions->end());
        delete byte_order;
        delete exceptions;

        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

XorCrypt::CipherData *XorCrypt::decrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len, CLIProgressIndicator *cli_interface) {
    try {
        CLIProgressIndicator::print_status("Started decryption");
        uint64_t k_idx = 0;
        auto pCipherData = new CipherData();

        auto *unique_byte_set = new std::vector<Byte *>(0xFF, nullptr),
                *byte_sets = new std::vector<Byte *>(0xFF, nullptr);
        for (bit i = 0; i < 16; i++) (*byte_sets)[i] = new Byte(i);
        auto *byte_order = new std::vector<bit>();

        uint64_t idx = 0, exception_partition = 0;
        bit parent_length = input[idx++];
        while (parent_length--) {
            bit parent = 0, bits_length = 0;
            extract_order(input[idx++], &parent, &bits_length);

            uint64_t child_count = 0, bits_idx = idx + uint64_t(bits_length);
            while (idx < bits_idx) {
                child_count <<= 8;
                child_count |= uint64_t(input[idx++]);
            }
            if ((*unique_byte_set)[parent] == nullptr) byte_order->push_back(parent);
            (*unique_byte_set)[parent] = (*byte_sets)[parent];
            (*unique_byte_set)[parent]->size = child_count;
            exception_partition += child_count;
        }
        uint64_t t_idx = idx;
        idx += exception_partition;

        cli_interface->set_status("Parsing header", length - exception_partition);
        uint64_t progress = 1;
        cli_interface->catch_progress(&progress);
        while (idx < length) {
            progress++;
            bit parent = 0, bits_length = 0;
            extract_order(input[idx++], &parent, &bits_length);
            uint64_t bits = uint64_t(bits_length) + idx;

            uint64_t node_idx = 0;
            while (idx < bits) {
                node_idx <<= 8;
                node_idx |= input[idx++];
            }
            if ((*unique_byte_set)[parent]->exceptions == nullptr) {
                (*unique_byte_set)[parent]->exceptions = new std::vector<uint64_t>();
            }
            (*unique_byte_set)[parent]->exceptions->push_back(node_idx);
        }
        idx = t_idx;

        cli_interface->set_status("Mapping stream", byte_order->size());
        progress = 1;
        for (auto &i: *byte_order) {
            progress++;
            Byte *pByte = (*unique_byte_set)[i];
            while (pByte->stream->size() != pByte->size) {
                bit data = input[idx++];
                if (k_idx == k_len) k_idx = 0;
                data ^= key[k_idx++];
                pByte->stream->push_back(data);
            }
        }
        delete[] input;

        cli_interface->set_status("Flushing byte stream", length);
        Byte *pByte = (*unique_byte_set)[(*byte_order)[0]];
        progress = 1;
        while (pByte->idx < pByte->size) {
            progress++;
            bit data = (*pByte->stream)[pByte->idx++];
            if (pByte->idx == pByte->size) delete pByte->stream;

            bit val = 0, next_parent = 0;
            extract_order(data, &val, &next_parent);
            data = pByte->val << 4;
            data |= val;

            pCipherData->data.push_back(data);
            if (next_parent == 0) {
                if (pByte->exceptions == nullptr || pByte->exp_idx >= pByte->exceptions->size()) continue;
                uint64_t exp_idx = (*pByte->exceptions)[pByte->exp_idx];
                if (pByte->idx - uint64_t(1) == exp_idx) {
                    pByte->exp_idx++;
                    pByte = (*unique_byte_set)[next_parent];
                }
                continue;
            }
            pByte = (*unique_byte_set)[next_parent];
        }
        delete unique_byte_set;
        delete byte_order;
        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

bool XorCrypt::process_file(std::string &src_path, std::string &dest_path, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface) {
    std::ifstream file(src_path, std::ios::binary);
    std::ofstream output_file(dest_path, std::ios::binary);
    if (!file.is_open()) return false;
    if (!output_file.is_open()) return false;
    cli_interface->set_status("Reading file", 0);

    auto *cipher_key = new std::vector<bit>();
    for (auto &i: key) cipher_key->push_back(reinterpret_cast<bit &>(i));

    file.seekg(0, std::ios::end);
    auto input_length = file.tellg();
    bit *input = new bit[input_length];
    file.seekg(0, std::ios::beg);
    file.read((char *) input, input_length);
    file.close();
    CLIProgressIndicator::print_status("Size: " + std::to_string(input_length) + " bytes");

    CipherData *res = to_encrypt ?
                      encrypt_bytes(input, input_length, reinterpret_cast<const bit *>(key.c_str()), key.length(), cli_interface) :
                      decrypt_bytes(input, input_length, reinterpret_cast<const bit *>(key.c_str()), key.length(), cli_interface);

    if (res->error) return false;
    cli_interface->set_status("Writing file", 0);
    output_file.write((char *) &res->data[0], int64_t(res->data.size()));
    output_file.close();
    delete res;
    return !file.is_open() && !output_file.is_open();
}

XorCrypt::CipherData *XorCrypt::process_string(std::string &str, std::string &key, bool to_encrypt, CLIProgressIndicator *cli_interface) {
    return to_encrypt ?
           encrypt_bytes(reinterpret_cast<const bit *>(str.c_str()), str.length(),
                         reinterpret_cast<const bit *>(key.c_str()), key.length(), cli_interface) :
           decrypt_bytes(reinterpret_cast<const bit *>(str.c_str()), str.length(),
                         reinterpret_cast<const bit *>(key.c_str()), key.length(), cli_interface);
}

XorCrypt::CipherData *XorCrypt::encrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface) {
    return process_string(str, key, true, cli_interface);
}

bool XorCrypt::encrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface) {
    return process_file(src_path, dest_path, key, true, cli_interface);
}

XorCrypt::CipherData *XorCrypt::decrypt_string(std::string &str, std::string &key, CLIProgressIndicator *cli_interface) {
    return process_string(str, key, false, cli_interface);
}

bool XorCrypt::decrypt_file(std::string &src_path, std::string &dest_path, std::string &key, CLIProgressIndicator *cli_interface) {
    return process_file(src_path, dest_path, key, false, cli_interface);
}
