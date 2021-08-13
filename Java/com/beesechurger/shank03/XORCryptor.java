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

import java.util.Arrays;
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
     * Since {@link #encrypt(byte[], byte[], boolean, ProcessListener)} and {@link #decrypt(byte[], byte[], ProcessListener)}
     * uses separate thread to process, this is an interface listener to handle result through {@link #onResult(byte[], String)}
     */
    public interface ProcessListener {
        /**
         * @param data Returned processed data,
         *             at this point @param `err` will be null
         * @param err  Returned error message if caused any,
         *             at this point @param `data` will be null
         */
        void onResult(byte[] data, String err);
    }

    private static final byte[] RANDOM_FLAG = "RANDOMIZED".getBytes();

    /**
     * Utility function to convert the byte array to string
     *
     * @return String
     */
    public static synchronized String getString(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte b : data) {
            out.append((char) b);
        }
        return out.toString();
    }

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
     * @param text       The input to be encrypted
     * @param key        The unique passcode for encrypting/decrypting text
     * @param listener   Interface to return data when processed
     * @param randomized Boolean whether to randomize the encryption
     * @apiNote : Randomization returns double the size of initial data
     */
    public static synchronized void encrypt(final byte[] text, final byte[] key, final boolean randomized, final ProcessListener listener) {
        if (text == null || key == null) {
            listener.onResult(null, "Text or Key NULL");
            return;
        }
        if (key.length > text.length) {
            listener.onResult(null, "Key length more than input length");
            return;
        }
        if (text.length < 6 || key.length < 6) {
            listener.onResult(null, "Text length less than 6");
            return;
        }
        try {
            final byte[] out = new byte[randomized ? (text.length * 2) + RANDOM_FLAG.length : text.length];
            new Thread(() -> {
                int k = 0, o_index = 0;
                if (randomized) {
                    for (int i = 0; i < RANDOM_FLAG.length; i++) {
                        out[i] = RANDOM_FLAG[i];
                        o_index++;
                    }
                }
                for (byte b : text) {
                    if (k == key.length) {
                        k = 0;
                    }
                    int c = new Random().nextInt(128);
                    out[o_index] = randomized ? (byte) (b ^ key[k] ^ c) : (byte) (b ^ key[k]);
                    o_index++;
                    if (randomized) {
                        out[o_index] = (byte) c;
                        o_index++;
                    }
                    k++;
                }
                listener.onResult(out, null);
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
    public static synchronized void decrypt(final byte[] input, final byte[] key, final ProcessListener listener) {
        if (input == null || key == null) {
            listener.onResult(null, "Text or Key NULL");
            return;
        }
        if (key.length < 6) {
            listener.onResult(null, "Key length less than 6");
            return;
        }
        try {
            byte[] fInput = handleRandomized(input);
            boolean randomized = fInput.length < input.length;
            int arrayLen = randomized ? fInput.length / 2 : fInput.length;
            final byte[] rands = new byte[fInput.length / 2], encryptedText = new byte[arrayLen], out = new byte[arrayLen];

            new Thread(() -> {
                if (randomized) {
                    int r_index = 0, e_index = 0;
                    for (int i = 0; i < fInput.length; i++) {
                        if (i % 2 == 0) {
                            rands[r_index] = fInput[i];
                            r_index++;
                        } else {
                            encryptedText[e_index] = fInput[i];
                            e_index++;
                        }
                    }
                } else {
                    System.arraycopy(fInput, 0, encryptedText, 0, fInput.length);
                }

                int k = 0, c = 0, o_index = 0;
                for (byte aByte : encryptedText) {
                    if (k == key.length) {
                        k = 0;
                    }
                    if (c == rands.length) {
                        c = 0;
                    }
                    out[o_index] = randomized ? (byte) (aByte ^ key[k] ^ rands[c]) : (byte) (aByte ^ key[k]);
                    o_index++;
                    k++;
                    c++;
                }
                listener.onResult(out, null);
            }, "Decryption Thread").start();
        } catch (Exception e) {
            listener.onResult(null, e.getLocalizedMessage());
        }
    }

    private static synchronized byte[] handleRandomized(byte[] data) {
        if (data.length < RANDOM_FLAG.length) {
            return data;
        }
        int flagCount = 0;
        for (int i = 0; i < RANDOM_FLAG.length; i++) {
            if (data[i] == RANDOM_FLAG[i]) {
                flagCount++;
            }
        }
        return flagCount == RANDOM_FLAG.length ? Arrays.copyOfRange(data, RANDOM_FLAG.length, data.length) : data;
    }
}
