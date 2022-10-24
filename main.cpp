#include <bitset>
#include <cstring>
#include <iostream>

#include "cli.h"
#include "xor_cryptor.h"

void print_help(bool error = false) {
    std::cout << "\n";
    if (!error) std::cout << "XOR Cryptor\n\n";
    std::cout << "Usage:\n - xor_cryptor -p -m e -f file_name...\n\n";
    std::cout << "Parameters:\n";
    std::cout << "\t-p            - Preserves the source file\n";
    std::cout << "\t-m <mode>     - mode is either 'e' (encryption) or 'd' (decryption)\n";
    std::cout << "\t-f <files>... - Encrypts/Decrypts the file(s) mentioned.\n";
}

struct Status : XorCryptor::StatusListener {
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

int exec_cli_file(int mode, bool preserve_src, const std::string &file_name, const std::string &key, CLIProgressIndicator *cli) {
    auto *status  = new Status(cli);
    auto *cryptor = new XorCryptor();
    cli->start_progress();

    std::string dest_file_name(file_name);
    bool        res;
    try {
        if (mode) {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) != std::string::npos) {
                cli->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(XorCryptor::FILE_EXTENSION);
            res = cryptor->encrypt_file(preserve_src, file_name, dest_file_name, key, status);
        } else {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) == std::string::npos) {
                std::cout << "This file is not for decryption\n";
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res            = cryptor->decrypt_file(preserve_src, file_name, dest_file_name, key, status);
        }
    } catch (std::exception &e) {
        std::cout << "Unknown error occurred\n";
        std::cout << e.what() << "\n";
        return 1;
    }
    if (res) std::cout << (mode ? "Encryption complete -> " + dest_file_name : "Decryption complete -> " + dest_file_name) << "\n";
    return !res;
}

void print_error(const std::string &error) {
    std::cout << "\nError: " << error << "\n";
    print_help(true);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help();
        return 0;
    }

    std::string args[argc];
    for (int i = 1; i < argc; i++) args[i] = argv[i];

    std::vector<std::string> files;

    int  mode         = 1;    // default: Encryption mode
    bool has_help     = false;
    bool preserve_src = false;
    for (int i = 0; i < argc; i++) {
        if (args[i] == "-p") preserve_src = true;
        if (args[i] == "-h" || args[i] == "--help") {
            has_help = true;
            break;
        }
        if (args[i] == "-m") {
            if (i + 1 >= argc) continue;
            if (args[i + 1] == "e") {
                mode = 1;
            } else if (args[i + 1] == "d") {
                mode = 0;
            } else {
                print_error("Invalid mode");
                return 1;
            }
        } else if (args[i] == "-f") {
            if (i + 1 >= argc) {
                print_error("No file(s) specified");
                return 1;
            }
            i++;
            while (i < argc && args[i][0] != '-') files.push_back(args[i++]);
        }
    }

    if (has_help) {
        print_help();
        return 0;
    }

    if (files.empty()) {
        print_error("No file(s) specified");
        return 1;
    }

    std::string key;
    std::cout << "Enter key: ";
    std::cin >> key;

    if (key.length() < 6) {
        std::cout << "Key cannot be less than 6 characters\n";
        return 1;
    }

    auto *cli = new CLIProgressIndicator();
    int   res = 0;
    for (auto &path : files) {
        if (std::filesystem::is_directory(path)) continue;
        if (exec_cli_file(mode, preserve_src, path, key, cli)) {
            cli->print_status("Failed to process file: \"" + path + "\"");
            res = 1;
        }
        cli->print_status("-----------------------");
    }
    cli->stop_progress();
    delete cli;
    return res;
}
