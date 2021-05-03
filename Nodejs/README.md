# XORCryptor

A Node.js module for quick randomized XOR encryption

### Installation

```shell
npm install xor-cryptor --save
```

### Usage

#### Javascript

```javascript
const xorCrypt = require('xor-cryptor');

let {encrypted, e_err} = xorCrypt.encrypt(text, key);
if (e_err !== undefined) {
    // Handle error
} else {
    // Handle return encrypted text
}

let {decrypted, d_err} = xorCrypt.decrypt(encrypted, key);
if (d_err !== undefined) {
    // Handle error
} else {
    // Handle return decrypted text
}
```

#### Typescript

```typescript
import {encrypt, decrypt} from 'xor-cryptor';

let {encrypted, e_err} = encrypt(text, key);
if (e_err !== undefined) {
    // Handle error
} else {
    // Handle return encrypted text
}

let {decrypted, d_err} = decrypt(encrypted, key);
if (d_err !== undefined) {
    // Handle error
} else {
    // Handle return decrypted text
}
```

### Tests

```shell
npm run test
```