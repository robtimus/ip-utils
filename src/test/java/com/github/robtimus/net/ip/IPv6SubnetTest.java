/*
 * IPv6SubnetTest.java
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import java.util.Optional;
import java.util.Spliterator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("nls")
class IPv6SubnetTest {

    @ParameterizedTest(name = "{0}/{1}: {2}")
    @MethodSource
    @DisplayName("size")
    void testSize(IPv6Address address, int prefixLength, int expectedSize) {
        IPv6Subnet subnet = address.startingSubnet(prefixLength);
        assertEquals(expectedSize, subnet.size());
        assertEquals(expectedSize, subnet.size());
    }

    static Arguments[] testSize() {
        IPv6Address address = IPv6Address.MIN_VALUE;
        return new Arguments[] {
                arguments(address, 0, Integer.MAX_VALUE),
                arguments(address, 8, Integer.MAX_VALUE),
                arguments(address, 16, Integer.MAX_VALUE),
                arguments(address, 24, Integer.MAX_VALUE),
                arguments(address, 28, Integer.MAX_VALUE),
                arguments(address, 32, Integer.MAX_VALUE),
                arguments(address, 40, Integer.MAX_VALUE),
                arguments(address, 48, Integer.MAX_VALUE),
                arguments(address, 64, Integer.MAX_VALUE),
                arguments(address, 72, Integer.MAX_VALUE),
                arguments(address, 80, Integer.MAX_VALUE),
                arguments(address, 88, Integer.MAX_VALUE),
                arguments(address, 96, Integer.MAX_VALUE),
                arguments(address, 97, Integer.MAX_VALUE),
                arguments(address, 98, 1073741824),
                arguments(address, 99, 536870912),
                arguments(address, 100, 268435456),
                arguments(address, 104, 16777216),
                arguments(address, 112, 65536),
                arguments(address, 120, 256),
                arguments(address, 126, 4),
                arguments(address, 127, 2),
                arguments(address, 128, 1),
        };
    }

    @Test
    @DisplayName("spliterator")
    void testSpliterator() {
        IPv6Subnet subnet = IPv6Address.MIN_VALUE.startingSubnet(0);
        Spliterator<?> spliterator = subnet.spliterator();
        // IPv6RangeSpliterator has its own tests
        assertEquals(IPv6RangeSpliterator.class, spliterator.getClass());
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence) and valueOf(CharSequence, int, int)")
    DynamicTest[] testValueOfCIDRNotation() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertThrows(NullPointerException.class, () -> IPv6Subnet.valueOf(null));
                    assertThrows(NullPointerException.class, () -> IPv6Subnet.valueOf(null, 0, 0));
                }),
                testValueOfCIDRNotationInvalidRoutingPrefix("::1/0", "::1", 0),
                testValueOfCIDRNotation("::1/128", 128, IPv6Address.LOCALHOST, IPv6Address.LOCALHOST),
                testValueOfCIDRNotation("::/0", 0, IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE),
                testValueOfCIDRNotation("12::/16", 16, IPv6Address.valueOf(0x0012_0000_0000_0000L, 0L),
                        IPv6Address.valueOf(0x0012_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34::/32", 32, IPv6Address.valueOf(0x0012_0034_0000_0000L, 0L),
                        IPv6Address.valueOf(0x0012_0034_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34:56::/48", 48, IPv6Address.valueOf(0x0012_0034_0056_0000L, 0L),
                        IPv6Address.valueOf(0x0012_0034_0056_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34:56:78::/64", 64, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34:56:78:90::/80", 80, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_FFFF_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34:56:78:90:ab::/96", 96, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00ab_FFFF_FFFFL)),
                testValueOfCIDRNotation("12:34:56:78:90:ab:cd::/112", 112, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00ab_00cd_FFFFL)),
                testValueOfCIDRNotation("12:34:56:78:90:ab:cd:ef/128", 128, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_00EFL),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_00EFL)),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/16", "12:34:56:78:90:ab:cd:ef", 16),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/32", "12:34:56:78:90:ab:cd:ef", 32),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/48", "12:34:56:78:90:ab:cd:ef", 48),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/64", "12:34:56:78:90:ab:cd:ef", 64),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/80", "12:34:56:78:90:ab:cd:ef", 80),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/96", "12:34:56:78:90:ab:cd:ef", 96),
                testValueOfCIDRNotationInvalidRoutingPrefix("12:34:56:78:90:ab:cd:ef/112", "12:34:56:78:90:ab:cd:ef", 112),
                testValueOfCIDRNotationInvalidPrefixLength(-1),
                testValueOfCIDRNotationInvalidPrefixLength(129),
                testValueOfCIDRNotationInvalidFormat("::"),
                testValueOfCIDRNotationInvalidFormat("::/x"),
                testValueOfCIDRNotationInvalidFormat("::1::/x"),
                testValueOfCIDRNotationInvalidFormat("127.0.0.1/12"),
        };
    }

    private DynamicTest testValueOfCIDRNotation(CharSequence cidrNotation, int expectedPrefixLength,
            IPv6Address expectedFrom, IPv6Address expectedTo) {

        return dynamicTest(cidrNotation.toString(), () -> {
            IPv6Subnet subnet = IPv6Subnet.valueOf(cidrNotation);
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            subnet = IPv6Subnet.valueOf("1" + cidrNotation + "1", 1, 1 + cidrNotation.length());
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidFormat(CharSequence cidrNotation) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidCIDRNotation(cidrNotation), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidRoutingPrefix(CharSequence cidrNotation, String routingPrefix, int prefixLength) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidRoutingPrefix(routingPrefix, prefixLength), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf("::1/" + prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("tryValueOfIPv6")
    DynamicTest[] testTryValueOfIPv6() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(Optional.empty(), IPv6Subnet.tryValueOfIPv6(null));
                    assertEquals(Optional.empty(), IPv6Subnet.tryValueOfIPv6(null, 0, 0));
                }),
                testTryValueOfIPv6("", Optional.empty()),
                testTryValueOfIPv6("::1/0", Optional.empty()),
                testTryValueOfIPv6("::1/128", Optional.of(IPv6Subnet.valueOf(IPv6Address.LOCALHOST, 128))),
                testTryValueOfIPv6("::/0", Optional.of(IPv6Subnet.valueOf(IPv6Address.MIN_VALUE, 0))),
                testTryValueOfIPv6("12::/16", Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0000_0000_0000L, 0L), 16))),
                testTryValueOfIPv6("12:34::/32", Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0000_0000L, 0L), 32))),
                testTryValueOfIPv6("12:34:56::/48", Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0000L, 0L), 48))),
                testTryValueOfIPv6("12:34:56:78::/64", Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0L), 64))),
                testTryValueOfIPv6("12:34:56:78:90::/80",
                        Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_0000_0000_0000L), 80))),
                testTryValueOfIPv6("12:34:56:78:90:ab::/96",
                        Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_0000_0000L), 96))),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd::/112",
                        Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_0000L), 112))),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/128",
                        Optional.of(IPv6Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_00EFL), 128))),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/16", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/32", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/48", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/64", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/80", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/96", Optional.empty()),
                testTryValueOfIPv6("12:34:56:78:90:ab:cd:ef/112", Optional.empty()),
                testTryValueOfIPv6("::1/-1", Optional.empty()),
                testTryValueOfIPv6("::1/129", Optional.empty()),
                testTryValueOfIPv6("::", Optional.empty()),
                testTryValueOfIPv6("::/x", Optional.empty()),
                testTryValueOfIPv6("::1::/x", Optional.empty()),
                testTryValueOfIPv6("127.0.0.1/12", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOfIPv6(String cidrNotation, Optional<IPv6Subnet> expected) {
        String displayName = String.valueOf(cidrNotation);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, IPv6Subnet.tryValueOfIPv6(cidrNotation));
            assertEquals(expected, IPv6Subnet.tryValueOfIPv6("1" + cidrNotation + "1", 1, 1 + cidrNotation.length()));
            assertEquals(expected, IPv6Subnet.tryValueOfIPv6("z" + cidrNotation + "z", 1, 1 + cidrNotation.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.tryValueOfIPv6(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.tryValueOfIPv6(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class,
                    () -> IPv6Subnet.tryValueOfIPv6(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.tryValueOfIPv6(cidrNotation, 0, -1));
        });
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence, int) and valueOf(IPv6Address, int)")
    DynamicTest[] testValueOfWithIPAddress() {
        CharSequence address = "12:34:56:78:90:ab:cd:ef";
        return new DynamicTest[] {
                dynamicTest("null CharSequence", () -> assertThrows(NullPointerException.class, () -> IPv6Subnet.valueOf((CharSequence) null, 1))),
                dynamicTest("null IPAddress", () -> assertThrows(NullPointerException.class, () -> IPv6Subnet.valueOf((IPv6Address) null, 1))),
                testValueOfWithIPAddressInvalidRoutingPrefix("::1", 0),
                testValueOfWithIPAddress("::1", 128, IPv6Address.LOCALHOST),
                testValueOfWithIPAddress("::", 0, IPv6Address.MAX_VALUE),
                testValueOfWithIPAddress("12::", 16, IPv6Address.valueOf(0x0012_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34::", 32, IPv6Address.valueOf(0x0012_0034_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34:56::", 48, IPv6Address.valueOf(0x0012_0034_0056_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34:56:78::", 64, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0xFFFF_FFFF_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34:56:78:90::", 80, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_FFFF_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34:56:78:90:ab::", 96, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_FFFF_FFFFL)),
                testValueOfWithIPAddress("12:34:56:78:90:ab:cd::", 112, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_FFFFL)),
                testValueOfWithIPAddress("12:34:56:78:90:ab:cd:ef", 128, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_00EFL)),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 16),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 32),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 48),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 64),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 80),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 96),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 112),
                testValueOfWithIPAddressInvalidPrefixLength(-1),
                testValueOfWithIPAddressInvalidPrefixLength(129),
        };
    }

    private DynamicTest testValueOfWithIPAddress(CharSequence address, int prefixLength, IPv6Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv6Address expectedFrom = IPv6Address.valueOf(address);
            IPv6Subnet subnet = IPv6Subnet.valueOf(address, prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidRoutingPrefix(CharSequence address, int prefixLength) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf(address, prefixLength));
            assertEquals(Messages.Subnet.invalidRoutingPrefix(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf("::1", prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("isIPv6Subnet")
    DynamicTest[] testIsIPv6Subnet() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(false, IPv6Subnet.isIPv6Subnet(null));
                    assertEquals(false, IPv6Subnet.isIPv6Subnet(null, 0, 0));
                }),
                testIsIPv6Subnet("", false),
                testIsIPv6Subnet("::1/0", false),
                testIsIPv6Subnet("::1/128", true),
                testIsIPv6Subnet("::/0", true),
                testIsIPv6Subnet("12::/16", true),
                testIsIPv6Subnet("12:34::/32", true),
                testIsIPv6Subnet("12:34:56::/48", true),
                testIsIPv6Subnet("12:34:56:78::/64", true),
                testIsIPv6Subnet("12:34:56:78:90::/80", true),
                testIsIPv6Subnet("12:34:56:78:90:ab::/96", true),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd::/112", true),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/128", true),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/16", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/32", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/48", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/64", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/80", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/96", false),
                testIsIPv6Subnet("12:34:56:78:90:ab:cd:ef/112", false),
                testIsIPv6Subnet("::/-1", false),
                testIsIPv6Subnet("::/129", false),
                testIsIPv6Subnet("::", false),
                testIsIPv6Subnet("::/x", false),
                testIsIPv6Subnet("::1::/x", false),
                testIsIPv6Subnet("127.0.0.1/12", false),
        };
    }

    private DynamicTest testIsIPv6Subnet(CharSequence s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, IPv6Subnet.isIPv6Subnet(s));
            assertEquals(expected, IPv6Subnet.isIPv6Subnet("1" + s + "1", 1, 1 + s.length()));
            assertEquals(expected, IPv6Subnet.isIPv6Subnet("z" + s + "z", 1, 1 + s.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.isIPv6Subnet(s, -1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.isIPv6Subnet(s, 0, s.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.isIPv6Subnet(s, s.length() + 1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv6Subnet.isIPv6Subnet(s, 0, -1));
        });
    }
}
