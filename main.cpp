#include "cli.h"
#include "xor_cryptor.h"
#include <cstring>
#include <iostream>
#include <unistd.h>

void print_help() {
    std::cout << "XOR Cryptor\n\n";
    std::cout << "Usage:\n - xor_cryptor -m e -f file_name\n\n";
    std::cout << "Parameters:\n";
    std::cout << "\t-m <mode> - mode is either 'e' (encrypt) or 'd' (decrypt)\n";
    std::cout << "\t-f <file_name> - Encrypts/Decrypts only the file mentioned.\n";
}

struct Status : XorCrypt::StatusListener {
    CLIProgressIndicator *progressIndicator;

    explicit Status(CLIProgressIndicator *indicator) : progressIndicator(indicator) {}

    void print_status(const std::string &status) override {
        progressIndicator->print_status(status);
    }

    void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) override {
        progressIndicator->update_status(status);
        progressIndicator->catch_progress(progress_ptr, total);
    }
};

int exec_cli_file(int mode, const std::string &file_name, const std::string &key) {
    auto *cli = new CLIProgressIndicator();
    auto *status = new Status(cli);
    cli->start_progress();

    std::string dest_file_name(file_name);
    bool res;
    try {
        if (mode) {
            if (dest_file_name.find(".xor") != std::string::npos) {
                cli->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(".xor");
            res = XorCrypt().encrypt_file(file_name, dest_file_name, key, status);
        } else {
            if (dest_file_name.find(".xor") == std::string::npos) {
                std::cout << "This file is not for decryption\n";
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res = XorCrypt().decrypt_file(file_name, dest_file_name, key, status);
        }
    } catch (std::exception &e) {
        std::cout << "Unknown error occurred\n";
        std::cout << e.what() << "\n";
        return 1;
    }
    cli->stop_progress();
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

    std::string key;
    std::cout << "Enter the key: ";
    std::cin >> key;

    return exec_cli_file(mode, std::string(f_val), key);
}
