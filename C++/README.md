# XORCryptor

For C++

### Usage

- Encrypting normal text
    ```c++
    #include <iostream>
    #include "xor-cryptor.hpp"

    int main() {
        std::string text, key;  // Take input

        // Encrypt
        XorCrypt::CipherData *output = XorCrypt::encrypt_string(text, key);

        if (output->err) {
            // Handle error
            std::cout << "Error: " << *output->err << "\n";
        } else {
            string encrypted;
            output->extract_string(&encrypted);
            std::cout << "Encrypted: " << encrypted << "\n";
        }

        // Decrypt
        std::string encryptedText;    // Take input
        XorCrypt::CipherData *output_dec = XorCrypt::decrypt_string(encryptedText, key);

        if (output_dec->err) {
            // Handle error
            std::cout << "Error: " << *output_dec->err << "\n";
        } else {
            string decrypted;
            output_dec->extract_string(&decrypted);
            std::cout << "Decrypted: " << decrypted << "\n";
        }
        return 0;
    }
    ```

### Special Thanks

**Ilya Polishchuk ([effolkronium](https://github.com/effolkronium))**
for [C++ random library](https://github.com/effolkronium/random)
