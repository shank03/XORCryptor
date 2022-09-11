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

XorCrypt::StatusListener::~StatusListener() = default;

void XorCrypt::write_node_property(std::vector<bit> *stream, bit parent, uint64_t value) const {
    mBitStream->to_bit_stream(value);
    parent = (parent << 4) | reinterpret_cast<bit &>(mBitStream->byte_length);

    stream->push_back(parent);
    mBitStream->write_to_stream(stream);
}

void XorCrypt::insert_node(std::vector<Byte *> *unique_byte_set, std::vector<bit> *exception_stream, bit parent, Node *node, uint64_t &idx) {
    bit data = (node->val << 4);
    if (node->next) {
        bit next_parent = node->next->val;
        if (next_parent == 0) {
            uint64_t bit_stream_idx = idx / 8ULL;
            while (bit_stream_idx >= exception_stream->size()) exception_stream->push_back(0);
            (*exception_stream)[bit_stream_idx] |= (bit(1) << bit(idx % 8ULL));
        }
        data |= next_parent;
    }
    (*unique_byte_set)[parent]->idx++;
    (*unique_byte_set)[parent]->stream->push_back(data);
}

template<typename Iterator>
void XorCrypt::process_stream(std::vector<bit> *ostream, Iterator begin, Iterator end, const XorCrypt::bit *key, uint64_t *k_idx, uint64_t k_len) const {
    for (auto it = begin; it != end; it++) {
        if (*k_idx == k_len) *k_idx = 0;
        bit ck = key[(*k_idx)++];
        ck = (ck >> 4) | (ck << 4);
        ostream->push_back(bit(*it ^ ck));
    }
}

void XorCrypt::e_map_bytes(const bit *input, uint64_t length, std::vector<bit> *exception_stream,
                           std::vector<Byte *> *unique_byte_set, std::vector<bit> *byte_order, uint64_t *itr) const {
    Node *pNode = new Node();
    catch_progress("Mapping Bytes", itr, length);
    for (; *itr < length; (*itr)++) {
        pNode->reset();
        bit parent = input[*itr] >> 4, data = input[*itr] & 0x0F;

        if ((*unique_byte_set)[parent] == nullptr) {
            (*unique_byte_set)[parent] = (*mByteSets)[parent];
            byte_order->push_back(parent);
        }
        pNode->val = data;
        (*unique_byte_set)[parent]->size++;

        if (*itr != length - 1) {
            bit next_parent = input[*itr + 1] >> 4;
            if ((*unique_byte_set)[next_parent] == nullptr) {
                (*unique_byte_set)[next_parent] = (*mByteSets)[next_parent];
                byte_order->push_back(next_parent);
            }
            if (parent != next_parent) pNode->next = (*unique_byte_set)[next_parent];
        }
        insert_node(unique_byte_set, exception_stream, parent, pNode, *itr);
    }
    delete[] input;
}

void XorCrypt::e_flush_streams(const bit *key, uint64_t k_len, XorCrypt::CipherData *pCipherData,
                               const std::vector<Byte *> *unique_byte_set, const std::vector<bit> *byte_order, uint64_t *itr) const {
    uint64_t k_idx = 0;
    catch_progress("Flushing byte stream", itr, byte_order->size());
    pCipherData->data->push_back(static_cast<bit>(byte_order->size()));
    for (auto &order: *byte_order) {
        Byte *pByte = (*unique_byte_set)[order];
        write_node_property(pCipherData->data, pByte->val, pByte->size);
    }
    *itr = 0;
    for (; *itr < byte_order->size(); (*itr)++) {
        Byte *pByte = (*unique_byte_set)[(*byte_order)[*itr]];
        process_stream<std::vector<bit>::iterator>(pCipherData->data, pByte->stream->begin(), pByte->stream->end(), key, &k_idx, k_len);
        delete pByte->stream;
    }
}

XorCrypt::CipherData *XorCrypt::encrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len) const {
    try {
        print_status("Started encryption");
        auto pCipherData = new CipherData();

        auto *unique_byte_set = new std::vector<Byte *>(0x10, nullptr);
        auto *byte_order = new std::vector<bit>(), *exception_stream = new std::vector<bit>();
        uint64_t itr = 0;

        e_map_bytes(input, length, exception_stream, unique_byte_set, byte_order, &itr);
        e_flush_streams(key, k_len, pCipherData, unique_byte_set, byte_order, &itr);

        uint64_t k_idx = 0;
        process_stream<std::vector<bit>::iterator>(pCipherData->data, exception_stream->begin(), exception_stream->end(), key, &k_idx, k_len);

        delete exception_stream;
        delete unique_byte_set;
        delete byte_order;
        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

void XorCrypt::d_parse_header(const bit *input, uint64_t length, const bit *key, uint64_t k_len, std::vector<bit> *exception_stream,
                              std::vector<Byte *> *unique_byte_set, std::vector<bit> *byte_order, uint64_t *idx, uint64_t *progress) const {
    uint64_t exception_partition = 0;
    uint64_t parent_length = input[(*idx)++];

    catch_progress("Parsing header", progress, parent_length);
    while (parent_length--) {
        (*progress)++;
        bit parent = input[*idx] >> 4;
        bit bits_length = input[(*idx)++] & 0x0F;

        uint64_t bits_value = 0, bits_idx = *idx + uint64_t(bits_length);
        while (*idx < bits_idx) bits_value = (bits_value << 8) | uint64_t(input[(*idx)++]);

        if ((*unique_byte_set)[parent] == nullptr) {
            (*unique_byte_set)[parent] = (*mByteSets)[parent];
            byte_order->push_back(parent);
        }
        (*unique_byte_set)[parent]->size = bits_value;
        exception_partition += bits_value;
    }

    uint64_t k_idx = 0;
    process_stream<const bit *>(exception_stream, input + *idx + exception_partition, input + length, key, &k_idx, k_len);
}

void XorCrypt::d_flush_stream(uint64_t length, XorCrypt::CipherData *pCipherData, std::vector<bit> *exception_stream,
                              const std::vector<Byte *> *unique_byte_set, const std::vector<bit> *byte_order, uint64_t *progress) const {
    Byte *pByte = (*unique_byte_set)[(*byte_order)[0]];
    catch_progress("Flushing byte stream", progress, length);
    uint64_t g_idx = 0;
    while (pByte->idx < pByte->size) {
        (*progress)++, g_idx++;
        bit data = (*pByte->stream)[pByte->idx++];
        if (pByte->idx == pByte->size) delete pByte->stream;

        bit val = data >> 4, next_parent = data & 0x0F;
        data = (pByte->val << 4) | val;
        pCipherData->data->push_back(data);

        if (next_parent == 0) {
            uint64_t idx = g_idx - 1ULL;
            uint64_t bit_stream_idx = idx / 8ULL;
            if (bit_stream_idx >= exception_stream->size()) continue;

            bit linked_mask = (*exception_stream)[bit_stream_idx] & (bit(1) << bit(idx % 8ULL));
            if (linked_mask != 0) pByte = (*unique_byte_set)[next_parent];
            continue;
        }
        pByte = (*unique_byte_set)[next_parent];
    }
}

XorCrypt::CipherData *XorCrypt::decrypt_bytes(const bit *input, uint64_t length, const bit *key, uint64_t k_len) const {
    try {
        print_status("Started decryption");
        uint64_t k_idx = 0;
        auto pCipherData = new CipherData();

        auto *unique_byte_set = new std::vector<Byte *>(0x10, nullptr);
        auto *byte_order = new std::vector<bit>(), *exception_stream = new std::vector<bit>();

        uint64_t idx = 0, progress = 1;
        d_parse_header(input, length, key, k_len, exception_stream, unique_byte_set, byte_order, &idx, &progress);

        progress = 1;
        catch_progress("Mapping stream", &progress, byte_order->size());
        for (auto &i: *byte_order) {
            progress++;
            Byte *pByte = (*unique_byte_set)[i];
            process_stream<const bit *>(pByte->stream, input + idx, input + idx + pByte->size, key, &k_idx, k_len);
            idx += pByte->size;
        }
        delete[] input;

        progress = 1;
        d_flush_stream(length, pCipherData, exception_stream, unique_byte_set, byte_order, &progress);

        delete exception_stream;
        delete unique_byte_set;
        delete byte_order;
        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

void XorCrypt::print_speed(uint64_t fileSize, uint64_t time_end) {
    const uint64_t KILO_BYTE = uint64_t(1024) * uint64_t(sizeof(unsigned char));
    const uint64_t MEGA_BYTE = uint64_t(1024) * KILO_BYTE;

    std::string unit;
    if (fileSize >= MEGA_BYTE) {
        unit = " MB/s";
        fileSize /= MEGA_BYTE;
    } else {
        unit = " KB/s";
        fileSize /= KILO_BYTE;
    }

    long double speed = (long double) fileSize / time_end * 1000.0;
    std::stringstream str_speed;
    str_speed << std::fixed << std::setprecision(2) << speed;
    print_status("Time taken = " + std::to_string(time_end) + " [ms] - " + str_speed.str() + unit);
}

bool XorCrypt::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt) {
    reset_bytes();

    std::ifstream file(src_path, std::ios::binary);
    std::ofstream output_file(dest_path, std::ios::binary);
    if (!file.is_open()) return false;
    if (!output_file.is_open()) return false;

    catch_progress("Reading file", nullptr, 0);
    file.seekg(0, std::ios::end);
    auto input_length = file.tellg();
    bit *input = new bit[input_length];

    file.seekg(0, std::ios::beg);
    file.read((char *) input, input_length);
    file.close();

    print_status("File size: " + std::to_string(input_length) + " bytes");

    bit *cipher_key = new bit[key.length()];
    for (uint64_t i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    CipherData *res = to_encrypt
                      ? encrypt_bytes(input, input_length, cipher_key, key.length())
                      : decrypt_bytes(input, input_length, cipher_key, key.length());
    if (res->error) return false;
    uint64_t time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_speed(input_length, time_end);

    catch_progress("Writing file", nullptr, 0);
    output_file.write((char *) &(*res->data)[0], int64_t(res->data->size()));
    output_file.close();
    delete res;
    return !file.is_open() && !output_file.is_open();
}

XorCrypt::CipherData *XorCrypt::process_string(const std::string &str, const std::string &key, bool to_encrypt) {
    reset_bytes();

    bit *input = new bit[str.length()], *cipher_key = new bit[key.length()];
    for (uint64_t i = 0; i < str.length(); i++) input[i] = str[i];
    for (uint64_t i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    return to_encrypt ?
           encrypt_bytes(input, str.length(), cipher_key, key.length()) :
           decrypt_bytes(input, str.length(), cipher_key, key.length());
}

XorCrypt::CipherData *XorCrypt::encrypt_string(const std::string &str, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_string(str, key, true);
}

bool XorCrypt::encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, true);
}

XorCrypt::CipherData *XorCrypt::decrypt_string(const std::string &str, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_string(str, key, false);
}

bool XorCrypt::decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, false);
}
