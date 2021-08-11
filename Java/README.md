# XORCrypt

Module for `Java / Kotlin`

### Installation

- Download `XORCryptor.jar` from the releases
- Import it in your project

### Usage

#### Java:

```java
import com.beesechurger.shank03.XORCryptor;

class Sample {
    public static void main(String[] args) {
        String text;    // Take input
        String key;     // Take input

        XORCryptor.encrypt(text.getBytes(), key.getBytes(), (data, err) -> {
            if (err != null) {
                // Handle error
                System.out.println("Error: " + err);
            } else {
                // Handle encrypted text
                System.out.println("Encrypted: " + XORCryptor.getString(data));
            }
        });

        String encrypted;   // Some encrypted text
        XORCryptor.decrypt(encrypted.getBytes(), key.getBytes(), (data, err) -> {
            if (err != null) {
                // Handle error
                System.out.println("Error: " + err);
            } else {
                // Handle decrypted text
                System.out.println("Decrypted: " + XORCryptor.getString(data));
            }
        });
    }
}
```

-----------------------------------------------------------------

#### Kotlin

```kotlin
import com.beesechurger.shank03.XORCryptor

fun main() {
    val text = ""
    val key = ""

    XORCryptor.encrypt(text.toByte(), key.toByte()) { data, err ->
        if (err != null) {
            println("Error: $err")
        } else {
            println("Encrypted: ${XORCryptor.getString(data)}")
        }
    }

    val encrypted = ""
    XORCryptor.decrypt(encrypted.toByte(), key.toByte()) { data, err ->
        if (err != null) {
            println("Error: $err")
        } else {
            println("Decrypted: ${XORCryptor.getString(data)}")
        }
    }
}
```
