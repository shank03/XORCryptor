# XORCryptor

Encrypts or decrypts the text or file using XOR bitwise operation.

The bytes are mapped and then XORed in a way that any other key
could attempt to decrypt it but not get the correct result.

### Installing CLI

```shell
git clone https://github.com/shank03/XORCryptor.git -b cli-linux
cd XORCryptor
sudo make install
```

Executable file will be present in `bin` as `xor_cryptor(.exe)`

### Usage

It will ask for key everytime you encrypt or decrypt some file

```text
xor_cryptor -h                       # help
xor_cryptor -m e -f info.txt         # (light) encrypts the info.txt

xor_cryptor -m d -f info.txt.xrc     # (light) decrypts the info.txt.xrc
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
    `- info.txt.xrc
```

If we are to decrypt this `info.txt.xrc`,

we'll run `xor_cryptor -m d -f info.txt.xrc`

This will decrypt the `info.txt.xrc` into `info.txt`

### NOTE !

> DO NOT FORGET THE KEY YOU GAVE FOR ENCRYPTION
