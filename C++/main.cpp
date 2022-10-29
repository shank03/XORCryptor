#include <iostream>

#include "xor_cryptor.h"

int main() {
    std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis ornare.";
    std::string key   = "secret_key";
    std::string encrypted_result;
    XorCryptor::encrypt(input, key, &encrypted_result);
    std::cout << "\nEncrypted:\n"
              << encrypted_result << "\n\n";

    std::string decrypted_result;
    XorCryptor::decrypt(encrypted_result, key, &decrypted_result);
    std::cout << "Decrypted:\n"
              << decrypted_result << "\n\n";
    return 0;
}
