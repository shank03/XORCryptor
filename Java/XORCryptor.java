/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
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

public class XORCryptor {

    private XORCryptor() {
    }

    private static int generateXORMask(int v) {
        int mask = 0, vt = v;
        while (vt != 0) {
            mask += (vt & 1);
            vt >>= 1;
        }
        mask |= ((8 - mask) << 4);
        mask = (mask ^ ((mask >> 4) | ((mask << 4) & 0xF0)));
        return (mask ^ v) & 0xFF;
    }

    private static void generateCipherBytes(int[] cipher, int[] table, boolean toEncrypt) {
        for (int i = 0; i < cipher.length; i++)
            cipher[i] = generateXORMask(cipher[i]);

        int mask = 0, mode = 0, count, shift, value, bitMask;
        for (int i = 0; i <= 255; i++) {
            count = 4;
            shift = 0;
            value = i;
            while (count != 0) {
                bitMask = value & 3;
                if (bitMask > 1)
                    mask |= (1 << shift);
                if (bitMask == 0 || bitMask == 3)
                    mode |= (1 << shift);
                count--;
                shift++;
                value >>= 2;
            }
            mask = ((mask << 4) | mode) & 0xFF;
            table[toEncrypt ? i : mask] = toEncrypt ? mask : i;
            mask = mode = 0;
        }
    }

    private static void encryptBytes(int[] src, int[] cipher, int[] table) {
        int i, mask = 0, mode = 0;
        for (i = 0; i < src.length; i++) {
            if ((i & 1) == 1) {
                mask |= (table[src[i]] & 0xF0);
                mode |= ((table[src[i]] & 0xF) << 4);
                mode ^= mask;

                src[i] = mode ^ cipher[i % cipher.length];
                src[i - 1] = mask ^ cipher[(i - 1) % cipher.length];
                mask = mode = 0;
            } else {
                mask |= (table[src[i]] >> 4);
                mode |= (table[src[i]] & 0xF);
            }
        }
        if ((src.length & 1) == 1) {
            mode ^= mask;
            int value = (mask << 4) | mode;
            src[i - 1] = value ^ cipher[(i - 1) % cipher.length];
        }
    }

    private static void decryptBytes(int[] src, int[] cipher, int[] table) {
        int i, k = 0;
        boolean odd = (src.length & 1) == 1;
        int mask, mode;
        for (i = 0; i < src.length; i++) {
            mask = src[i] ^ cipher[i % cipher.length];
            if (i == (src.length - 1) && odd) {
                mode = mask & 0xF;
                mask >>= 4;
                mode ^= mask;
            } else {
                i++;
                mode = src[i] ^ cipher[i % cipher.length];
                mode ^= mask;

                src[k++] = table[((mask & 0xF) << 4) | (mode & 0xF)];
                mask >>= 4;
                mode >>= 4;
            }
            src[k++] = table[((mask & 0xF) << 4) | (mode & 0xF)];
        }
    }

    private static String processData(String inputData, String key, boolean toEncrypt) {
        if (inputData == null || inputData.isEmpty())
            return null;
        if (key == null || key.length() < 6)
            return null;

        int[] src = new int[inputData.length()], cipher = new int[key.length()], table = new int[256];
        for (int i = 0; i < inputData.length(); i++)
            src[i] = inputData.charAt(i);

        for (int i = 0; i < key.length(); i++)
            cipher[i] = key.charAt(i);
        generateCipherBytes(cipher, table, toEncrypt);

        if (toEncrypt) {
            encryptBytes(src, cipher, table);
        } else {
            decryptBytes(src, cipher, table);
        }

        StringBuilder sb = new StringBuilder();
        for (int j : src)
            sb.append((char) j);
        return sb.toString();
    }

    public static String encrypt(String input, String key) {
        return processData(input, key, true);
    }

    public static String decrypt(String input, String key) {
        return processData(input, key, false);
    }
}
