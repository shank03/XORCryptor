# XORCryptor

For C++

### Usage

```c++
#include <iostream>
#include "xor-cryptor.h"

int main() {
    std::string text, key;  // Take input

    // Encrypt
    std::vector<xorCrypt::byte> input(text.begin(), text.end()), cipherKey(key.begin(), key.end());
    xorCrypt::XORCipherData output;
    xorCrypt::encrypt(input, cipherKey, &output);

    if (output.err == NULL_STR) {
        // Handle encrypted text
        std::cout << xorCrypt::getString(output.data) << "\n";
    } else {
        // Handle error
        std::cout << "Error: " << output.err << "\n";
    }

    // Decrypt
    std::vector<xorCrypt::byte> encryptedText;    // Take input
    xorCrypt::XORCipherData output_dec;
    xorCrypt::decrypt(encryptedText, key, &output_dec);

    if (output_dec.err == NULL_STR) {
        // Handle decrypted text
        std::cout << xorCrypt::getString(output_dec.data) << "\n";
    } else {
        // Handle error
        std::cout << "Error: " << output_dec.err << "\n";
    }
    return 0;
}

```

### Special Thanks
**Ilya Polishchuk ([effolkronium](https://github.com/effolkronium))** for [C++ random library](https://github.com/effolkronium/random)
