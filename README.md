# XORCryptor

Encrypts or decrypts the text or file using XOR bitwise operation.

### Installing CLI

```shell
git clone https://github.com/shank03/XORCryptor.git -b cli
cd XORCryptor
sudo make install
```

### Usage

It will ask for key everytime you encrypt or decrypt some file

```text
xor_cryptor -h # help
xor_cryptor -m e -f info.txt    # encrypts the info.txt
xor_cryptor -m d -f info.txt.xor    # decrypts the info.txt.xor
```

### How CLI works

Let's say we have:

```text
random_folder
    `- info.txt
```

And we run `xor_cryptor -m e -f info.txt`, now we'll have:

```text
random_folder
    `- info.txt
    `- info.txt.xor
```

If we are to decrypt this `info.txt.xor`,

we'll run `xor_cryptor -m d -f info.txt.xor`

This will decrypt the `info.txt.xor` into `info.txt` (i.e. overwriting contents of `info.txt`)

### NOTE !

> DO NOT FORGET THE KEY YOU GAVE FOR ENCRYPTION
