# XORCryptor

For C++

### Usage

```c++
#include <iostream>
#include "xor-cryptor.h"

int main() {
    std::string text, key;  // Take input

    // Encrypt
    std::string encrypted[2];
    xorCrypt::encrypt(text, key, encrypted);

    if (encrypted[1] == NULL_STR) {
        // Handle encrypted text
        std::cout << encrypted[0] << "\n";
    } else {
        // Handle error
        std::cout << "Error: " << encrypted[1] << "\n";
    }

    // Decrypt
    std::string someRandomEncryptedText, decrypted[2];
    xorCrypt::decrypt(someRandomEncryptedText, key, decrypted);

    if (decrypted[1] == NULL_STR) {
        // Handle decrypted text
        std::cout << decrypted[0] << "\n";
    } else {
        // Handle error
        std::cout << "Error: " << decrypted[1] << "\n";
    }
    return 0;
}

```

### Special Thanks
**Ilya Polishchuk ([effolkronium](https://github.com/effolkronium))** for [C++ random library](https://github.com/effolkronium/random)
