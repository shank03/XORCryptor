#include "xor_cryptor.h"
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
    return (stat(name, &buffer) == 0);
}

int main(int argc, char *argv[]) {
    CLI *cli = new CLI();
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

    return cli->exec_cli(mode, file_name, key);
}
