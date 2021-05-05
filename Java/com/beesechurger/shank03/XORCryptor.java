/*
 * Copyright (c) 2021, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

package com.beesechurger.shank03;

import java.util.Random;

/**
 * XORCryptor Class
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input, key and randomized generated character.
 * <p>
 * date: 02-May-2021
 */
public class XORCryptor {

    // Private constructor
    private XORCryptor() {
    }

    /**
     * Since {@link #encrypt(String, String, ProcessListener)} and {@link #decrypt(String, String, ProcessListener)}
     * uses separate thread to process, this is an interface listener to handle result through {@link #onResult(String, String)}
     */
    public interface ProcessListener {
        /**
         * @param data Returned processed data,
         *             at this point @param `err` will be null
         * @param err  Returned error message if caused any,
         *             at this point @param `data` will be null
         */
        void onResult(String data, String err);
    }

    /**
     * Array of alphabets to randomly generate from {@link #getRandChar()}
     */
    private static final char[] ALPHABETS = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

    /**
     * Function that encrypts the provided text
     * <p>
     * Implementation:
     * <pre> {@code
     * XORCryptor.encrypt(text, key, (data, err) -> {
     *     if (err != null) {
     *         // handle error
     *     } else {
     *         // handle returned encrypted data
     *     }
     * });
     * }</pre>
     *
     * @param text     The input to be encrypted
     * @param key      The unique passcode for encrypting/decrypting text
     * @param listener Interface to return data when processed
     */
    public static synchronized void encrypt(final String text, final String key, final ProcessListener listener) {
        if (text == null || key == null) {
            listener.onResult(null, "Text or Key NULL");
            return;
        }
        if (key.length() > text.length()) {
            listener.onResult(null, "Key length more than input length");
            return;
        }
        if (text.length() < 6 || key.length() < 6) {
            listener.onResult(null, "Text length less than 6");
            return;
        }
        try {
            final StringBuilder out = new StringBuilder();
            new Thread(() -> {
                int k = 0;
                for (int i = 0; i < text.length(); i++) {
                    if (k == key.length()) {
                        k = 0;
                    }
                    int c = getRandChar();
                    out.append((char) ((int) text.charAt(i) ^ (int) key.charAt(k) ^ c)).append((char) c);
                    k++;
                }
                listener.onResult(out.toString(), null);
            }, "Encryption Thread").start();
        } catch (Exception e) {
            listener.onResult(null, e.getLocalizedMessage());
        }
    }

    /**
     * Function that decrypts the encrypted text
     * <p>
     * Implementation:
     * <pre> {@code
     * XORCryptor.decrypt(text, key, (data, err) -> {
     *     if (err != null) {
     *         // handle error
     *     } else {
     *         // handle returned decrypted data
     *     }
     * });
     * }</pre>
     *
     * @param input    The encrypted text to be decrypted
     * @param key      The unique passcode for encrypting/decrypting text
     * @param listener Interface to return data when processed
     */
    public static synchronized void decrypt(final String input, final String key, final ProcessListener listener) {
        if (input == null || key == null) {
            listener.onResult(null, "Text or Key NULL");
            return;
        }
        if (key.length() < 6) {
            listener.onResult(null, "Key length less than 6");
            return;
        }
        try {
            final StringBuilder rands = new StringBuilder(), encryptedText = new StringBuilder(), out = new StringBuilder();
            new Thread(() -> {
                for (int i = 0; i < input.length(); i++) {
                    if (i % 2 == 0) {
                        rands.append(input.charAt(i));
                    } else {
                        encryptedText.append(input.charAt(i));
                    }
                }

                int k = 0, c = 0;
                for (int i = 0; i < encryptedText.length(); i++) {
                    if (k == key.length()) {
                        k = 0;
                    }
                    if (c == rands.length()) {
                        c = 0;
                    }
                    out.append((char) ((int) encryptedText.charAt(i) ^ (int) key.charAt(k) ^ (int) rands.charAt(c)));
                    k++;
                    c++;
                }
                listener.onResult(out.toString(), null);
            }, "Decryption Thread").start();
        } catch (Exception e) {
            listener.onResult(null, e.getLocalizedMessage());
        }
    }

    /**
     * Function to generate random character from {@link #ALPHABETS}
     *
     * @return ascii of random character which is randomly capitalized
     */
    private static synchronized int getRandChar() {
        char chr = ALPHABETS[new Random().nextInt(ALPHABETS.length)];
        int cap = new Random().nextInt(2);
        return cap == 1 ? chr - 32 : chr;
    }
}
