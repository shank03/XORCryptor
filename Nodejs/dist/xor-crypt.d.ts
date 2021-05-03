/**
 * Function that encrypts the provided text
 *
 * Implementation:
 * ```
 * const xorCrypt = require('xor-cryptor');
 *
 * let {encrypted, e_err} = xorCrypt.encrypt(text, key);
 * if (e_err !== undefined) {
 *     // handle error
 * } else {
 *     // handle encrypted text
 * }
 * ```
 *
 * @param text     The input to be encrypted
 * @param key      The unique passcode for encrypting/decrypting text
 */
export declare function encrypt(text: string, key: string): {
    encrypted: string | undefined;
    err: string | undefined;
};
/**
 * Function that decrypts the encrypted text
 *
 * Implementation:
 * ```
 * const xorCrypt = require('xor-cryptor');
 *
 * let {decrypted, d_err} = xorCrypt.decrypt(encrypted, key);
 * if (d_err !== undefined) {
 *     // handle error
 * } else {
 *     // handle decrypted text
 * }
 * ```
 * @param input    The encrypted text to be decrypted
 * @param key      The unique passcode for encrypting/decrypting text
 */
export declare function decrypt(input: string, key: string): {
    decrypted: string | undefined;
    err: string | undefined;
};
