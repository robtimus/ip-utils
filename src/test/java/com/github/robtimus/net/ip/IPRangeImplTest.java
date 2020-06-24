/*
 * IPRangeImplTest.java
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@SuppressWarnings("nls")
class IPRangeImplTest {

    @Nested
    class IPv4 {

        @Test
        @DisplayName("from and to")
        void testFromAndTo() {
            IPv4Address from = IPv4Address.valueOf(0x12345678);
            IPv4Address to = IPv4Address.valueOf(0x87654321);
            IPv4Range ipRange = new IPRangeImpl.IPv4(from, to);
            assertSame(from, ipRange.from());
            assertSame(to, ipRange.to());
        }

        @Test
        @DisplayName("toString")
        void testToString() {
            IPv4Address from = IPv4Address.valueOf(12, 34, 56, 78);
            IPv4Address to = IPv4Address.valueOf(87, 65, 43, 21);
            IPv4Range ipRange = new IPRangeImpl.IPv4(from, to);
            assertEquals("[12.34.56.78...87.65.43.21]", ipRange.toString());
            // test caching
            assertSame(ipRange.toString(), ipRange.toString());
        }
    }

    @Nested
    class IPv6 {

        @Test
        @DisplayName("from and to")
        void testFromAndTo() {
            IPv6Address from = IPv6Address.valueOf(0x12345678, 0x12345678);
            IPv6Address to = IPv6Address.valueOf(0x87654321, 0x87654321);
            IPv6Range ipRange = new IPRangeImpl.IPv6(from, to);
            assertSame(from, ipRange.from());
            assertSame(to, ipRange.to());
        }

        @Test
        @DisplayName("toString")
        void testToString() {
            IPv6Address from = IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF);
            IPv6Address to = IPv6Address.valueOf(0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12);
            IPv6Range ipRange = new IPRangeImpl.IPv6(from, to);
            assertEquals("[12:34:56:78:90:ab:cd:ef...ef:cd:ab:90:78:56:34:12]", ipRange.toString());
            // test caching
            assertSame(ipRange.toString(), ipRange.toString());
        }
    }
}
