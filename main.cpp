#include "xor_cryptor.hpp"
#include <string>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

void print_help() {
    cout << "XOR Cryptor\n\n";
    cout << "Usage:\n - xor_c -m 1 -f file_name\n\n";
    cout << "Parameters:\n";
    cout << "\t-m <mode> - mode is either 'e' (encrypt) or 'd' (decrypt)\n";
    cout << "\t-f <file_name> - Encrypts/Decrypts only the file mentioned.\n";
}

bool file_exists(const char *name) {
    struct stat buffer{};
    return (stat(name, &buffer) == 0);
}

int exec_cli(int mode, string &file_name, string &key) {
    function<void(string stat, bool)> callback = [](const string &stat, bool print = false) -> void {
        if (print) {
            std::cout << "Status: " << stat << "\n";
            return;
        }
        std::cout.flush();
        std::cout << string(10 + stat.length() * 2, ' ') << "\r";
        std::cout.flush();
        std::cout << "Status: " << stat << "\r";
    };

    string dest_file_name(file_name);
    bool res;
    if (mode) {
        if (dest_file_name.find(".xor") != string::npos) {
            cout << "This file is not for encryption\n";
            return 1;
        }
        dest_file_name.append(".xor");
        try {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            res = XorCrypt::encrypt_file(file_name, dest_file_name, key, &callback);

            auto time_end = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - begin).count();
            callback("Time taken = " + to_string(time_end) + " [ms]", true);
        } catch (exception &e) {
            cout << "Unknown error occurred\n";
            cout << e.what() << "\n";
            return 1;
        }
    } else {
        if (dest_file_name.find(".xor") == string::npos) {
            cout << "This file is not for decryption\n";
            return 1;
        }
        dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
        try {
            std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
            res = XorCrypt::decrypt_file(file_name, dest_file_name, key, &callback);

            auto time_end = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - begin).count();
            callback("Time taken = " + to_string(time_end) + " [ms]", true);
        } catch (exception &e) {
            cout << "Unknown error occurred\n";
            cout << e.what() << "\n";
            return 1;
        }
    }
    cout << (res ?
             (mode ? "Encryption complete -> " + dest_file_name : "Decryption complete -> " + dest_file_name) :
             (mode ? "Encryption failed" : "Decryption failed"))
         << "\n";
    return 0;
}

int main(int argc, char *argv[]) {
    char *m_val = nullptr, *f_val = nullptr;
    opterr = 0;

    if (argc == 2 &&
        (strcmp(argv[1], "-h") == 0 ||
         strcmp(argv[1], "-help") == 0 ||
         strcmp(argv[1], "--help") == 0)) {
        print_help();
        return 0;
    }

    int opt;
    while ((opt = getopt(argc, argv, "m:f:")) != -1) {
        if (opt == 'm') m_val = optarg;
        if (opt == 'f') f_val = optarg;
    }
    if (m_val == nullptr) {
        cout << "Invalid args. Use -h for help\n";
        return 1;
    }
    if (f_val == nullptr) {
        cout << "Invalid args. Use -h for help\n";
        return 1;
    }

    int mode;
    if (strcmp(m_val, "e") == 0) {
        mode = 1;
    } else if (strcmp(m_val, "d") == 0) {
        mode = 0;
    } else {
        cout << "Invalid args for -m mode\n";
        return 1;
    }

    if (!file_exists(f_val)) {
        cout << "File doesn't exists\n";
        return 1;
    }

    string file_name = string(f_val), key;
    cout << "Enter the key: ";
    cin >> key;

    return exec_cli(mode, file_name, key);
}
