# XORCryptor

Encrypts or decrypts the text or file using XOR bitwise operation.

[About info.](About.md)

### CLI

This cli encrypts or decrypts the file(s) in synchronized multi-buffered multithreading way.

So the only bottleneck is your disk read/write speed.

### Installing CLI

```bash
git clone https://github.com/shank03/XORCryptor.git -b cli
cd XORCryptor
git submodule init
git submodule update
```

#### Windows

- Make sure have MSVC 2022 installed for compilation
- Run `install.bat` as administrator
- Add `C:\Program Files\XORCryptorCLI\` to environment variables

#### Linux
- Make sure you have `gcc g++ make cmake ninja-build`
- Run `sudo ./install.sh`

## Usage
<details>
<summary>Click to expand</summary>

It will ask for key everytime you encrypt or decrypt some file

```shell
$ xor_cryptor_cli [-p] [-r] -[e/d] -f [files...] [folders...]
```

### Encrypt

```shell
$ xor_cryptor_cli -e -f file.ext
```

```
Before command:         After command:

random_folder           random_folder
    |- some_fld             |- some_fld
    |   |- t.txt            |   |- t.txt
    |   |- p.txt            |   |- p.txt
    |   |- in_fld           |   |- in_fld
    |       |- v.mp4        |       |- v.mp4
    |- file.ext             |- file.ext.xrc
```

### With Folder

```shell
$ xor_cryptor_cli -e -f file.ext some_fld
```

```
Before command:         After command:

random_folder           random_folder
    |- some_fld             |- some_fld
    |   |- t.txt            |   |- t.txt.xrc
    |   |- p.txt            |   |- p.txt.xrc
    |   |- in_fld           |   |- in_fld
    |       |- v.mp4        |       |- v.mp4
    |- file.ext             |- file.ext.xrc
```

### Preserve source

```shell
$ xor_cryptor_cli -p -e -f file.ext some_fld
```

```
Before command:         After command:

random_folder           random_folder
    |- some_fld             |- some_fld
        |- t.txt            |   |- t.txt
        |- p.txt            |   |- t.txt.xrc
        |- in_fld           |   |- p.txt
        |   |- v.mp4        |   |- p.txt.xrc
        |- file.ext         |   |- in_fld
                            |       |- v.mp4
                            |- file.ext
                            |- file.ext.xrc
```

### Iterate Recursively

```shell
$ xor_cryptor_cli -r -e -f file.ext some_fld
```

```
Before command:         After command:

random_folder           random_folder
    |- some_fld             |- some_fld
    |   |- t.txt            |   |- t.txt.xrc
    |   |- p.txt            |   |- p.txt.xrc
    |   |- in_fld           |   |- in_fld
    |       |- v.mp4        |       |- v.mp4.xrc
    |- file.ext             |- file.ext.xrc
```
</details>

### NOTE !

> DO NOT FORGET THE KEY YOU GAVE FOR ENCRYPTION
