# XORCryptor

Encrypts or decrypts the text or file using XOR bitwise operation.

[More info.](About.md)

**[General Library](https://github.com/shank03/XORCryptor/tree/lib)**

### CLI

This cli encrypts or decrypts the file(s) in synchronized multi-buffered multithreading way.

So the only bottleneck is your disk read/write speed.

### Installing CLI

```shell
git clone https://github.com/shank03/XORCryptor.git -b cli
cd XORCryptor
sudo make install
```

Executable file will be present in `bin` as `xor_cryptor(.exe)`

## Usage

It will ask for key everytime you encrypt or decrypt some file

```shell
$ xor_cryptor [-p] [-r] -m [e/d] -f [files...] [folders...]
```

### Encrypt

```shell
$ xor_cryptor -m e -f file.ext
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
$ xor_cryptor -m e -f file.ext some_fld
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
$ xor_cryptor -p -m e -f file.ext some_fld
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
$ xor_cryptor -r -m e -f file.ext some_fld
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

### NOTE !

> DO NOT FORGET THE KEY YOU GAVE FOR ENCRYPTION
