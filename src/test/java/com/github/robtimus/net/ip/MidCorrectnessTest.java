/*
 * MidCorrectnessTest.java
 * Copyright 2022 Rob Spoor
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("nls")
class MidCorrectnessTest {

    /*
     * Tests that the mid calculations are correct by checking more cases.
     * To not let the tests run too long, parts are limited to only 4 bits.
     */

    private static final int SIGN_BIT = 1 << 3;
    private static final int OTHER_BITS = ~SIGN_BIT & 0xF;

    @Test
    @DisplayName("single part")
    void testSinglePart() {
        for (int address1 = 0; address1 <= 0xF; address1++) {
            for (int address2 = 0; address2 <= 0xF; address2++) {
                int mid = mid(address1, address2);

                int expected = (address1 + address2) >>> 1;

                assertEquals(expected, mid, String.format("mismatch for address1 = %d and address2 = %d", address1, address2));
            }
        }
    }

    @Test
    @DisplayName("two parts")
    void testTwoParts() {
        for (int address1 = 0; address1 <= 0xFF; address1++) {
            for (int address2 = 0; address2 <= 0xFF; address2++) {
                int low1 = address1 & 0xF;
                int high1 = (address1 & 0xF0) >>> 4;

                int low2 = address2 & 0xF;
                int high2 = (address2 & 0xF0) >>> 4;

                int midLow = mid(low1, low2);
                int midHigh = mid(high1, high2);

                int overflowLow = overflowLow(high1, high2);
                if (overflowLow != 0) {
                    int newMidLow = (midLow + overflowLow) & 0xF;
                    if (compareUnsigned(midLow, newMidLow) > 0) {
                        // midLowAddress overflows to midHighAddress
                        midHigh++;
                    }
                    midLow = newMidLow;
                }

                int mid = midLow | (midHigh << 4);

                int expected = (address1 + address2) >>> 1;

                assertEquals(expected, mid, String.format("mismatch for address1 = %d and address2 = %d", address1, address2));
            }
        }
    }

    private static int mid(int low, int high) {
        return (positiveMid(low, high) + signMid(low, high)) & 0xF;
    }

    private static int positiveMid(int low, int high) {
        int positiveLow = low & OTHER_BITS;
        int positiveHigh = high & OTHER_BITS;
        return (positiveLow + positiveHigh) >>> 1;
    }

    private static int signMid(int low, int high) {
        int signLow = low & SIGN_BIT;
        int signHigh = high & SIGN_BIT;
        if (signLow == signHigh) {
            // Both sign bits 0 or both 1; the mid is the same
            return signLow;
        }
        // Exactly one sign bit is set; the mid is the sign bit divided by 2 (using bit shift)
        return SIGN_BIT >>> 1;
    }

    private static int overflowLow(int low, int high) {
        int bitLow = low & 1;
        int bitHigh = high & 1;
        return bitLow == bitHigh ? 0 : SIGN_BIT;
    }

    private static int compareUnsigned(int x, int y) {
        assert x >= 0;
        assert y >= 0;
        return Integer.compare(x, y);
    }
}
