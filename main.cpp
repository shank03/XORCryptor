#include "cli.h"
#include "xor_cryptor.h"
#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

void print_help() {
    std::cout << "XOR Cryptor\n\n";
    std::cout << "Usage:\n - xor_c -m 1 -f file_name\n\n";
    std::cout << "Parameters:\n";
    std::cout << "\t-m <mode> - mode is either 'e' (encrypt) or 'd' (decrypt)\n";
    std::cout << "\t-f <file_name> - Encrypts/Decrypts only the file mentioned.\n";
}

bool file_exists(const char *name) {
    struct stat buffer{};
    int res = stat(name, &buffer);
    return res == 0 && S_ISREG(buffer.st_mode);
}

int exec_cli(int mode, std::string &file_name, std::string &key) {
    auto *cli = new CLIProgressIndicator();
    cli->start_progress();

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
            res = XorCrypt::encrypt_file(file_name, dest_file_name, key, cli);

            auto time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
            CLIProgressIndicator::print_status("Time taken = " + std::to_string(time_end) + " [ms]");
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
            res = XorCrypt::decrypt_file(file_name, dest_file_name, key, cli);

            auto time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
            CLIProgressIndicator::print_status("Time taken = " + std::to_string(time_end) + " [ms]");
        } catch (std::exception &e) {
            std::cout << "Unknown error occurred\n";
            std::cout << e.what() << "\n";
            return 1;
        }
    }
    std::cout << (res ?
                  (mode ? "Encryption complete -> " + dest_file_name : "Decryption complete -> " + dest_file_name) :
                  (mode ? "Encryption failed" : "Decryption failed")) << "\n";
    return 0;
}

int main(int argc, char *argv[]) {
    char *m_val = nullptr, *f_val = nullptr;
    opterr = 0;

    if (argc == 1 || (argc == 2 &&
                      (strcmp(argv[1], "-h") == 0 ||
                       strcmp(argv[1], "-help") == 0 ||
                       strcmp(argv[1], "--help") == 0))) {
        print_help();
        return 0;
    }

    int opt;
    while ((opt = getopt(argc, argv, "m:f:")) != -1) {
        if (opt == 'm') m_val = optarg;
        if (opt == 'f') f_val = optarg;
    }
    if (m_val == nullptr) {
        std::cout << "Invalid args. Use -h for help\n";
        return 1;
    }
    if (f_val == nullptr) {
        std::cout << "Invalid args. Use -h for help\n";
        return 1;
    }

    int mode;
    if (strcmp(m_val, "e") == 0) {
        mode = 1;
    } else if (strcmp(m_val, "d") == 0) {
        mode = 0;
    } else {
        std::cout << "Invalid args for -m mode\n";
        return 1;
    }

    if (!file_exists(f_val)) {
        std::cout << "File doesn't exists\n";
        return 1;
    }

    std::string file_name = std::string(f_val), key;
    std::cout << "Enter the key: ";
    std::cin >> key;

    return exec_cli(mode, file_name, key);
}
