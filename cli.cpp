#include "xor_cryptor.h"

void CLI::start_progress() {
    std::thread indicator_thread([this]() -> void {
        std::vector<std::string> progress_indicator{"-", "\\", "|", "/", "-"};
        int idx = 0, last_len = (int) mPreIndicatorText.length();
        while (idx != -1) {
            if (idx == progress_indicator.size()) idx = 0;

            int len = 0;
            std::cout.flush();
            std::cout << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << mPreIndicatorText << " " << progress_indicator[idx++];
            len += (int) mPreIndicatorText.length() + 3;
            if (mTotal != 0) {
                float percentage = (mProgress * 100.0) / mTotal;
                std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
                len += 20;
            }
            last_len = len;
            std::cout << "\r";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    indicator_thread.detach();
}

void CLI::print_status(const std::string &stat) {
    std::cout << stat << "\n";
}

void CLI::set_status(std::string stat, long double t) {
    mPreIndicatorText = std::move(stat);
    mTotal = t;
}

void CLI::set_progress(long double progress) {
    mProgress = progress;
}

int CLI::exec_cli(int mode, std::string &file_name, std::string &key) {
    start_progress();

    std::string dest_file_name(file_name);
    bool res;
    if (mode) {
        if (dest_file_name.find(".xor") != std::string::npos) {
            std::cout << "This file is not for encryption\n";
            return 1;
        }
        dest_file_name.append(".xor");
        try {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            res = XorCrypt::encrypt_file(file_name, dest_file_name, key, this);

            auto time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
            print_status("Time taken = " + std::to_string(time_end) + " [ms]");
        } catch (std::exception &e) {
            std::cout << "Unknown error occurred\n";
            std::cout << e.what() << "\n";
            return 1;
        }
    } else {
        if (dest_file_name.find(".xor") == std::string::npos) {
            std::cout << "This file is not for decryption\n";
            return 1;
        }
        dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
        try {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            res = XorCrypt::decrypt_file(file_name, dest_file_name, key, this);

            auto time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
            print_status("Time taken = " + std::to_string(time_end) + " [ms]");
        } catch (std::exception &e) {
            std::cout << "Unknown error occurred\n";
            std::cout << e.what() << "\n";
            return 1;
        }
    }
    std::cout << (res ?
                  (mode ? "Encryption complete -> " + dest_file_name : "Decryption complete -> " + dest_file_name) :
                  (mode ? "Encryption failed" : "Decryption failed"))
              << "\n";
    return 0;
}
