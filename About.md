## XORCryptor

Components for encrypting and decrypting:
  - [Generate Mask](#generate-mask)
  - [Generate Table](#generate-table)
  - [Encrpytion](#encrpytion)
  - [Decryption](#decryption)

### Generate Mask

This mask is an array generated from input key.

We generate a `pseudo-mask: 0000 0000` from a byte `b`, where MSB is count of `0s` and LSB is count of `1s` in `b`.

Mask of the byte `b` = `b ^ pseudo-mask`

### Generate Table

This table is an array of size 256.

Here's how each index is filled:
```
in the bits,
01 = 0 \ mode = 0
10 = 1 /

11 = 1 \ mode = 1
00 = 0 /

K     = 01 00 10 11 = 75
01/10 =  0  0  1  1 = mask
11/00 =  0  1  0  1 = mode

// for encrypting
=> table[75] = mask_mode = 0011_0101

// for decrypting
=> table[0011_0101] = 75
```

### Encrpytion

```
for every 2 subsequent characters (i.e. arr[0]; arr[1]; then arr[2] arr[3]):
    mask and mode are generated from the table,

    where,
    mask[i] = 4 bits of MSB of table[src[i]]
    mode[i] = 4 bits of LSB of table[src[i]]

    then,
    src[i]      = mask[i + 1]_mask[i]
    src[i + 1]  = mode[i + 1]_mode[i]

    then,
    src[i]      = mask ^ cipher
    src[i + 1]  = mode ^ cipher

```

### Decryption

```
for every 2 subsequent chars:
    mask_f = src[i]
    mode_f = src[i + 1]
    
    mask    = first 4 bits of mask_f
    mode    = first 4 bits of mode_f
    src[i]  = table[mask_mode]
    
    mask        = next 4 bits of mask_f
    mode        = next 4 bits of mode_f
    src[i + 1]  = table[mask_mode]
```
