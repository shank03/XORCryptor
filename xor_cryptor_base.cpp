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

#include "xor_cryptor_base.h"

XorCryptor_Base::StatusListener::~StatusListener() = default;

void XorCryptor_Base::print_speed(byte64 fileSize, byte64 time_end) {
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
    print_status("Processed bytes in " + std::to_string(time_end) + " [ms] - " + str_speed.str() + unit);
}

void XorCryptor_Base::print_status(const std::string &status) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->print_status(status);
}

void XorCryptor_Base::catch_progress(const std::string &status, XorCryptor_Base::byte64 *progress_ptr, XorCryptor_Base::byte64 total) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->catch_progress(status, progress_ptr, total);
}
