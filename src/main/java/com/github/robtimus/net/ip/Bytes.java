/*
 * Bytes.java
 * Copyright 2019 Rob Spoor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.robtimus.net.ip;

import java.math.BigInteger;

final class Bytes {

    // octet constants
    // OSHIFTx means shift x octets
    static final int OSHIFT0 = 0 * Byte.SIZE;
    static final int OSHIFT1 = 1 * Byte.SIZE;
    static final int OSHIFT2 = 2 * Byte.SIZE;
    static final int OSHIFT3 = 3 * Byte.SIZE;
    static final int OSHIFT4 = 4 * Byte.SIZE;
    static final int OSHIFT5 = 5 * Byte.SIZE;
    static final int OSHIFT6 = 6 * Byte.SIZE;
    static final int OSHIFT7 = 7 * Byte.SIZE;
    static final int OMASK = 0xFF;
    private static final long LOMASK = OMASK;
    // hextet constants
    // HSHIFT is shifting a single hextet
    static final long HSHIFT = 2 * Byte.SIZE;
    // HSHIFTx means shift x hextets
    static final long HSHIFT0 = 0L * HSHIFT;
    static final long HSHIFT1 = 1L * HSHIFT;
    static final long HSHIFT2 = 2L * HSHIFT;
    static final long HSHIFT3 = 3L * HSHIFT;
    static final long HMASK = 0xFFFFL;

    private static final int INT_SIGN_BIT = 1 << 31;
    private static final int INT_OTHER_BITS = ~INT_SIGN_BIT;

    private Bytes() {
        throw new Error("cannot create instances of " + getClass().getName()); //$NON-NLS-1$
    }

    static byte[] intToAddress(int address) {
        byte[] result = new byte[IPv4Address.BYTES];
        result[0] = (byte) ((address >> OSHIFT3) & OMASK);
        result[1] = (byte) ((address >> OSHIFT2) & OMASK);
        result[2] = (byte) ((address >> OSHIFT1) & OMASK);
        result[3] = (byte) ((address >> OSHIFT0) & OMASK);
        return result;
    }

    static int addressToInt(byte[] address) {
        return ((address[0] & OMASK) << OSHIFT3)
                | ((address[1] & OMASK) << OSHIFT2)
                | ((address[2] & OMASK) << OSHIFT1)
                | ((address[3] & OMASK) << OSHIFT0);
    }

    static byte[] longsToAddress(long highAddress, long lowAddress) {
        byte[] result = new byte[IPv6Address.BYTES];
        result[0] = (byte) ((highAddress >> OSHIFT7) & OMASK);
        result[1] = (byte) ((highAddress >> OSHIFT6) & OMASK);
        result[2] = (byte) ((highAddress >> OSHIFT5) & OMASK);
        result[3] = (byte) ((highAddress >> OSHIFT4) & OMASK);
        result[4] = (byte) ((highAddress >> OSHIFT3) & OMASK);
        result[5] = (byte) ((highAddress >> OSHIFT2) & OMASK);
        result[6] = (byte) ((highAddress >> OSHIFT1) & OMASK);
        result[7] = (byte) ((highAddress >> OSHIFT0) & OMASK);
        result[8] = (byte) ((lowAddress >> OSHIFT7) & OMASK);
        result[9] = (byte) ((lowAddress >> OSHIFT6) & OMASK);
        result[10] = (byte) ((lowAddress >> OSHIFT5) & OMASK);
        result[11] = (byte) ((lowAddress >> OSHIFT4) & OMASK);
        result[12] = (byte) ((lowAddress >> OSHIFT3) & OMASK);
        result[13] = (byte) ((lowAddress >> OSHIFT2) & OMASK);
        result[14] = (byte) ((lowAddress >> OSHIFT1) & OMASK);
        result[15] = (byte) ((lowAddress >> OSHIFT0) & OMASK);
        return result;
    }

    static long addressToHighAddress(byte[] address) {
        return ((address[0] & LOMASK) << OSHIFT7)
                | ((address[1] & LOMASK) << OSHIFT6)
                | ((address[2] & LOMASK) << OSHIFT5)
                | ((address[3] & LOMASK) << OSHIFT4)
                | ((address[4] & LOMASK) << OSHIFT3)
                | ((address[5] & LOMASK) << OSHIFT2)
                | ((address[6] & LOMASK) << OSHIFT1)
                | ((address[7] & LOMASK) << OSHIFT0);
    }

    static long addressToLowAddress(byte[] address) {
        return ((address[8] & LOMASK) << OSHIFT7)
                | ((address[9] & LOMASK) << OSHIFT6)
                | ((address[10] & LOMASK) << OSHIFT5)
                | ((address[11] & LOMASK) << OSHIFT4)
                | ((address[12] & LOMASK) << OSHIFT3)
                | ((address[13] & LOMASK) << OSHIFT2)
                | ((address[14] & LOMASK) << OSHIFT1)
                | ((address[15] & LOMASK) << OSHIFT0);
    }

    static long addressToHighAddress(BigInteger address) {
        long result = 0;
        for (int i = address.bitLength() - 1; i >= Long.SIZE; i--) {
            result <<= 1L;
            result |= address.testBit(i) ? 1 : 0;
        }
        return result;
    }

    static long addressToLowAddress(BigInteger address) {
        long result = 0;
        for (int i = Math.min(address.bitLength(), Long.SIZE) - 1; i >= 0; i--) {
            result <<= 1L;
            result |= address.testBit(i) ? 1 : 0;
        }
        return result;
    }

    static int mid(int low, int high) {
        int positiveLow = low & INT_OTHER_BITS;
        int positiveHigh = high & INT_OTHER_BITS;
        return ((positiveLow + positiveHigh) >>> 1) + midSignBit(low & INT_SIGN_BIT, high & INT_SIGN_BIT);
    }

    private static int midSignBit(int low, int high) {
        return low == high ? low : 1 << 30;
    }
}
