"use strict";
/*
 * Cryptor Class
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input, key and randomized generated character.
 *
 * @author Shashank Verma (shank03) <shashank.verma2002@gmail.com>
 * date: 02-May-2021
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = void 0;
/**
 * Array of alphabets to randomly generate from {@link getRandChar}
 */
var ALPHABETS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
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
function encrypt(text, key) {
    if (text == null || key == null) {
        return { encrypted: undefined, err: "Text or Key NULL" };
    }
    if (key.length > text.length) {
        return { encrypted: undefined, err: "Key length more than input length" };
    }
    if (text.length < 6) {
        return { encrypted: undefined, err: "Text length less than 6" };
    }
    try {
        var out = "";
        var k = 0;
        for (var i = 0; i < text.length; i++) {
            if (k === key.length)
                k = 0;
            var c = getRandChar();
            var crypt = text[i].charCodeAt(0) ^ key[k].charCodeAt(0) ^ c;
            out += String.fromCharCode(crypt) + String.fromCharCode(c);
            k++;
        }
        return { encrypted: out, err: undefined };
    }
    catch (e) {
        return { encrypted: undefined, err: "Err: " + e.message };
    }
}
exports.encrypt = encrypt;
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
function decrypt(input, key) {
    if (input == null || key == null) {
        return { decrypted: undefined, err: "Text or Key NULL" };
    }
    try {
        var out = "", rands = "", encrypted = "";
        for (var s = 0; s < input.length; s++) {
            if (s % 2 === 0) {
                rands += input[s];
            }
            else {
                encrypted += input[s];
            }
        }
        var k = 0, c = 0;
        for (var i = 0; i < encrypted.length; i++) {
            if (k === key.length)
                k = 0;
            if (c === rands.length)
                c = 0;
            out += String.fromCharCode(encrypted[i].charCodeAt(0) ^ key[k].charCodeAt(0) ^ rands[c].charCodeAt(0));
            k++;
            c++;
        }
        return { decrypted: out, err: undefined };
    }
    catch (e) {
        return { decrypted: undefined, err: "Err: " + e.message };
    }
}
exports.decrypt = decrypt;
/**
 * Function to generate random character from {@link ALPHABETS}
 *
 * @return ascii of random character which is randomly capitalized
 */
function getRandChar() {
    var char = ALPHABETS[Math.floor(Math.random() * 26)];
    var cap = Math.floor(Math.random() * 2);
    return cap === 1 ? char.toUpperCase().charCodeAt(0) : char.charCodeAt(0);
}
