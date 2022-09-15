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

XorCryptor::StatusListener::~StatusListener() = default;

void XorCryptor::write_node_property(std::vector<byte> *stream, byte parent, byte64 value) const {
    mBitStream->to_bit_stream(value);
    parent = (parent << 4) | reinterpret_cast<byte &>(mBitStream->byte_length);

    stream->push_back(parent);
    mBitStream->write_to_stream(stream);
}

void XorCryptor::insert_node(ByteNode *pByte, ByteStream *exception_stream, Node *pNode, byte64 &idx) {
    byte data = (pNode->val << 4);
    if (pNode->next) {
        byte next_parent = pNode->next->val;
        if (next_parent == 0) {
            byte64 bit_stream_idx = idx / 8ULL;
            while (bit_stream_idx >= exception_stream->size) exception_stream->push_back(0);
            exception_stream->data[bit_stream_idx] |= (byte(1) << byte(idx % 8ULL));
        }
        data |= next_parent;
    }
    pByte->idx++;
    pByte->byte_stream->push_back(data);
}

template<typename OStream, typename Iterator>
void XorCryptor::process_stream(OStream *ostream, Iterator begin, Iterator end, const XorCryptor::byte *cipher_key, byte64 *key_idx, byte64 key_length) const {
    for (auto it = begin; it != end; it++) {
        if (*key_idx == key_length) *key_idx = 0;
        byte ck = cipher_key[(*key_idx)++];
        ck = (ck >> 4) | (ck << 4);
        ostream->push_back(byte(*it ^ ck));
    }
}

void XorCryptor::e_map_bytes(const byte *input_bytes, byte64 input_length, ByteStream *exception_stream,
                             ByteNode **unique_byte_set, ByteStream *byte_order, byte64 *itr) const {
    Node *pNode = new Node();
    catch_progress("Mapping Bytes", itr, input_length);

    *itr = 0;
    for (; *itr < input_length; (*itr)++) {
        byte parent = input_bytes[*itr] >> 4;
        if (unique_byte_set[parent]->size == 0) byte_order->push_back(parent);
        unique_byte_set[parent]->size++;
    }
    for (byte64 i = 0; i < 0x10; i++) unique_byte_set[i]->allocate_byte_stream();

    *itr = 0;
    for (; *itr < input_length; (*itr)++) {
        pNode->reset();
        byte parent = input_bytes[*itr] >> 4, data = input_bytes[*itr] & 0x0F;
        pNode->val = data;

        if (*itr != input_length - 1) {
            byte next_parent = input_bytes[*itr + 1] >> 4;
            if (parent != next_parent) pNode->next = unique_byte_set[next_parent];
        }
        insert_node(unique_byte_set[parent], exception_stream, pNode, *itr);
    }
    delete[] input_bytes;
}

void XorCryptor::e_flush_streams(const byte *cipher_key, byte64 key_length, CipherData *pCipherData,
                                 ByteNode **unique_byte_set, const ByteStream *byte_order, byte64 *itr) const {
    byte64 key_idx = 0;
    catch_progress("Flushing byte data", itr, byte_order->size);
    pCipherData->data->push_back(static_cast<byte>(byte_order->size));
    *itr = 0;
    for (; *itr < byte_order->size; (*itr)++) {
        ByteNode *pByte = unique_byte_set[byte_order->data[*itr]];
        write_node_property(pCipherData->data, pByte->val, pByte->size);
    }
    *itr = 0;
    for (; *itr < byte_order->size; (*itr)++) {
        ByteNode *pByte = unique_byte_set[byte_order->data[*itr]];
        process_stream<std::vector<byte>, byte *>
                (pCipherData->data, pByte->byte_stream->data, pByte->byte_stream->data + pByte->byte_stream->size, cipher_key, &key_idx, key_length);
        delete pByte->byte_stream;
    }
}

XorCryptor::CipherData *XorCryptor::encrypt_bytes(const byte *input_bytes, byte64 input_length, const byte *cipher_key, byte64 key_length) const {
    try {
        print_status("Started encryption");
        auto pCipherData = new CipherData();

        auto **unique_byte_set = new ByteNode *[0x10];
        for (byte i = 0; i < 0x10; i++) unique_byte_set[i] = new ByteNode(i);

        byte64 exception_thresh = input_length;
        if (input_length % 8ULL) exception_thresh += 8ULL;
        exception_thresh /= 8ULL;

        auto *byte_order = new ByteStream(0x10), *exception_stream = new ByteStream(exception_thresh);
        exception_stream->push_back(0);

        byte64 itr = 0;
        e_map_bytes(input_bytes, input_length, exception_stream, unique_byte_set, byte_order, &itr);
        e_flush_streams(cipher_key, key_length, pCipherData, unique_byte_set, byte_order, &itr);
        delete[] unique_byte_set;
        delete byte_order;

        byte64 k_idx = 0;
        process_stream<std::vector<byte>, byte *>
                (pCipherData->data, exception_stream->data, exception_stream->data + exception_stream->size, cipher_key, &k_idx, key_length);
        delete exception_stream;
        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

void XorCryptor::d_parse_header(const byte *input, byte64 length, const byte *key, byte64 k_len, ByteStream *exception_stream,
                                ByteNode **unique_byte_set, ByteStream *byte_order, byte64 *idx, byte64 *progress) const {
    byte64 exception_partition = 0;
    byte64 parent_length = input[(*idx)++];

    catch_progress("Parsing header", progress, parent_length);
    while (parent_length--) {
        (*progress)++;
        byte parent = input[*idx] >> 4;
        byte bits_length = input[(*idx)++] & 0x0F;

        byte64 bits_value = 0, bits_idx = *idx + byte64(bits_length);
        while (*idx < bits_idx) bits_value = (bits_value << 8) | byte64(input[(*idx)++]);

        byte_order->push_back(parent);
        unique_byte_set[parent]->size = bits_value;
        unique_byte_set[parent]->allocate_byte_stream();
        exception_partition += bits_value;
    }

    byte64 key_idx = 0;
    process_stream<ByteStream, const byte *>
            (exception_stream, input + *idx + exception_partition, input + length, key, &key_idx, k_len);
}

void XorCryptor::d_flush_stream(byte64 length, CipherData *pCipherData, ByteStream *exception_stream,
                                ByteNode **unique_byte_set, byte top, byte64 *progress) const {
    ByteNode *pByte = unique_byte_set[top];
    catch_progress("Flushing byte data", progress, length);
    byte64 g_idx = 0;
    while (pByte->idx < pByte->size) {
        (*progress)++, g_idx++;
        byte data = pByte->byte_stream->data[pByte->idx++];
        if (pByte->idx == pByte->size) delete pByte->byte_stream;

        byte val = data >> 4, next_parent = data & 0x0F;
        data = (pByte->val << 4) | val;
        pCipherData->data->push_back(data);

        if (next_parent == 0) {
            byte64 idx = g_idx - 1ULL;
            byte64 bit_stream_idx = idx / 8ULL;
            if (bit_stream_idx >= exception_stream->size) continue;

            byte linked_mask = exception_stream->data[bit_stream_idx] & (byte(1) << byte(idx % 8ULL));
            if (linked_mask != 0) pByte = unique_byte_set[next_parent];
            continue;
        }
        pByte = unique_byte_set[next_parent];
    }
}

XorCryptor::CipherData *XorCryptor::decrypt_bytes(const byte *input_bytes, byte64 input_length, const byte *cipher_key, byte64 key_length) const {
    try {
        print_status("Started decryption");
        auto pCipherData = new CipherData();

        auto **unique_byte_set = new ByteNode *[0x10];
        for (byte i = 0; i < 0x10; i++) unique_byte_set[i] = new ByteNode(i);

        byte64 exception_thresh = input_length;
        if (input_length % 8ULL) exception_thresh += 8ULL;
        exception_thresh /= 8ULL;
        auto *byte_order = new ByteStream(0x10), *exception_stream = new ByteStream(exception_thresh);

        byte64 idx = 0, progress = 1;
        d_parse_header(input_bytes, input_length, cipher_key, key_length, exception_stream, unique_byte_set, byte_order, &idx, &progress);

        progress = 1;
        catch_progress("Mapping data", &progress, byte_order->size);
        byte64 key_idx = 0;
        for (byte64 i = 0; i < byte_order->size; i++) {
            progress++;
            ByteNode *pByte = unique_byte_set[byte_order->data[i]];
            process_stream<ByteStream, const byte *>(pByte->byte_stream, input_bytes + idx, input_bytes + idx + pByte->size, cipher_key, &key_idx, key_length);
            idx += pByte->size;
        }
        delete[] input_bytes;

        progress = 1;
        d_flush_stream(input_length, pCipherData, exception_stream, unique_byte_set, byte_order->data[0], &progress);

        delete exception_stream;
        delete byte_order;
        delete[] unique_byte_set;
        return pCipherData;
    } catch (std::exception &e) {
        return new CipherData(true);
    }
}

void XorCryptor::print_speed(byte64 fileSize, byte64 time_end) {
    const byte64 KILO_BYTE = byte64(1024) * byte64(sizeof(unsigned char));
    const byte64 MEGA_BYTE = byte64(1024) * KILO_BYTE;

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

bool XorCryptor::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt) {
    std::ifstream file(src_path, std::ios::binary);
    std::ofstream output_file(dest_path, std::ios::binary);
    if (!file.is_open()) return false;
    if (!output_file.is_open()) return false;

    catch_progress("Reading file", nullptr, 0);
    file.seekg(0, std::ios::end);
    auto input_length = file.tellg();
    byte *input = new byte[input_length];

    file.seekg(0, std::ios::beg);
    file.read((char *) input, input_length);
    file.close();

    print_status("File size: " + std::to_string(input_length) + " bytes");

    byte *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    CipherData *res = to_encrypt
                      ? encrypt_bytes(input, input_length, cipher_key, key.length())
                      : decrypt_bytes(input, input_length, cipher_key, key.length());
    if (res->error) return false;
    byte64 time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_speed(input_length, time_end);

    catch_progress("Writing file", nullptr, 0);
    output_file.write((char *) &(*res->data)[0], int64_t(res->data->size()));
    output_file.close();
    delete res;
    return !file.is_open() && !output_file.is_open();
}

XorCryptor::CipherData *XorCryptor::process_string(const std::string &str, const std::string &key, bool to_encrypt) {
    byte *input = new byte[str.length()], *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < str.length(); i++) input[i] = str[i];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    return to_encrypt ?
           encrypt_bytes(input, str.length(), cipher_key, key.length()) :
           decrypt_bytes(input, str.length(), cipher_key, key.length());
}

XorCryptor::CipherData *XorCryptor::encrypt_string(const std::string &str, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_string(str, key, true);
}

bool XorCryptor::encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, true);
}

XorCryptor::CipherData *XorCryptor::decrypt_string(const std::string &str, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_string(str, key, false);
}

bool XorCryptor::decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, false);
}
