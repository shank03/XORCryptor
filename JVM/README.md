# XORCrypt

JVM module for `Java / Kotlin`

### Installation

- Download `XORCryptor.jar` from the releases
- Import it in your project

### Usage

```java
import com.beesechurger.shank03.XORCryptor;

class Sample {
    public static void main(String[] args) {
        String text;    // Take input
        String key;     // Take input

        XORCryptor.encrypt(text, key, (data, err) -> {
            if (err != null) {
                // Handle error
                System.out.println("Error: " + err);
            } else {
                // Handle encrypted text
                System.out.println("Encrypted: " + data);
            }
        });

        String encrypted;   // Some encrypted text
        XORCryptor.decrypt(encrypted, key, (data, err) -> {
            if (err != null) {
                // Handle error
                System.out.println("Error: " + err);
            } else {
                // Handle decrypted text
                System.out.println("Decrypted: " + data);
            }
        });
    }
}
```