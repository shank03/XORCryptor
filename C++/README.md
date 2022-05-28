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
        std::vector<XorCrypt::byte> input(text.begin(), text.end()), cipherKey(key.begin(), key.end());
        XorCrypt::CipherData *output = XorCrypt::encrypt(input, cipherKey, true /* or false */);

        if (output->err == nullptr) {
            // Handle encrypted text
            std::cout << XorCrypt::getString(*output->data) << "\n";
        } else {
            // Handle error
            std::cout << "Error: " << *output->err << "\n";
        }

        // Decrypt
        std::vector<XorCrypt::byte> encryptedText;    // Take input
        XorCrypt::CipherData *output_dec = XorCrypt::decrypt(encryptedText, key);

        if (output_dec->err == nullptr) {
            // Handle decrypted text
            std::cout << XorCrypt::getString(*output_dec->data) << "\n";
        } else {
            // Handle error
            std::cout << "Error: " << *output_dec->err << "\n";
        }
        return 0;
    }
    ```

- Encrypting Files

    ```c++
    #include <iostream>
    #include "xor-cryptor.hpp"

    int main() {
        // Input file
        std::ifstream inputFile("filename.ext", std::ios::binary);
        std::vector<XorCrypt::byte> bytes((std::istreambuf_iterator<char>(inputFile)), (std::istreambuf_iterator<char>()));
        inputFile.close();

        std::string key = "randomKey";
        std::vector<XorCrypt::byte> cipherKey(key.begin(), key.end());

        // Encrypt
        XorCrypt::CipherData *output = XorCrypt::encrypt(bytes, cipherKey, true /* or false */);
        if (output->err == nullptr) {
            // Handle encrypted data
            std::ofstream encryptedFile("encrypted_filename.ext", std::ios::out | std::ios::binary);
            std::copy(output->data->begin(), output->data->end(), std::ostreambuf_iterator<char>(encryptedFile));
            encryptedFile.close();
        } else {
            // Handle error
            std::cout << "Error: " << *output->err << "\n";
        }

        // Decrypt File
        std::ifstream fileEnc("encrypted_filename.ext", std::ios::binary);
        std::vector<XorCrypt::byte> encBytes((std::istreambuf_iterator<char>(fileEnc)), (std::istreambuf_iterator<char>()));

        XorCrypt::CipherData *output_dec = XorCrypt::decrypt(encBytes, cipherKey);
        if (output_dec->err == nullptr) {
            std::ofstream decryptedFile("decrypted_filename.ext", std::ios::out | std::ios::binary);
            std::copy(output_dec->data->begin(), output_dec->data->end(), std::ostreambuf_iterator<char>(decryptedFile));
            decryptedFile.close();
        }
        return 0;
    }
    ```

### Special Thanks

**Ilya Polishchuk ([effolkronium](https://github.com/effolkronium))**
for [C++ random library](https://github.com/effolkronium/random)
