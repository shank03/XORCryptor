# XORCryptor

Encrypts or decrypts the text or file using XOR bitwise operation.

The bytes are mapped and then XORed in a way that any other key
could attempt to decrypt it but not get the correct result.

### Installing CLI

```shell
git clone https://github.com/shank03/XORCryptor.git -b cli-linux
cd XORCryptor
sudo make install   # for linux
sudo make           # for windows
```

Executable file will be present in `bin` as `xor_cryptor(.exe)`

### Usage

It will ask for key everytime you encrypt or decrypt some file

```text
xor_cryptor -h                       # help
xor_cryptor -m e -f info.txt         # (light) encrypts the info.txt
xor_cryptor -m e0 -f info.txt        # (light) encrypts the info.txt
xor_cryptor -m e1 -f info.txt        # (heavy) encrypts the info.txt

xor_cryptor -m d -f info.txt.xrl     # (light) decrypts the info.txt.xrl
xor_cryptor -m d0 -f info.txt.xrl    # (light) decrypts the info.txt.xrl
xor_cryptor -m d1 -f info.txt.xor    # (heavy) decrypts the info.txt.xor
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
    `- info.txt.xrl     # or .xor based on encryption mode (e/e0/e1)
```

If we are to decrypt this `info.txt.xrl`,

we'll run `xor_cryptor -m d -f info.txt.xrl`

This will decrypt the `info.txt.xrl` into `info.txt` (i.e. overwriting contents of `info.txt`)

### NOTE !

> DO NOT FORGET THE KEY YOU GAVE FOR ENCRYPTION
