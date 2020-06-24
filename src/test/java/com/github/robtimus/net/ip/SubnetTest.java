/*
 * SubnetTest.java
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings("nls")
class SubnetTest {

    @Test
    @DisplayName("from and to")
    void testFromAndTo() {
        IPv4Address from = IPv4Address.valueOf(192, 168, 0, 0);
        IPv4Address to = IPv4Address.valueOf(192, 168, 255, 255);
        int prefixLength = 16;
        Subnet<?> subnet = new Subnet<IPv4Address>(from, to, prefixLength) {
            @Override
            public int size() {
                return 0;
            }
        };
        assertSame(from, subnet.from());
        assertSame(to, subnet.to());
    }

    @Test
    @DisplayName("routingPrefix and prefixLength")
    void testRoutingPrefixAndPrefixLength() {
        IPv4Address from = IPv4Address.valueOf(192, 168, 0, 0);
        IPv4Address to = IPv4Address.valueOf(192, 168, 255, 255);
        int prefixLength = 16;
        Subnet<?> subnet = new Subnet<IPv4Address>(from, to, prefixLength) {
            @Override
            public int size() {
                return 0;
            }
        };
        assertSame(from, subnet.routingPrefix());
        assertEquals(prefixLength, subnet.prefixLength());
    }

    @Test
    @DisplayName("toString")
    void testToString() {
        IPv4Address address = IPv4Address.LOCALHOST;
        Subnet<?> subnet = new TestSubnet(address);
        assertEquals("127.0.0.1/32", subnet.toString());
        // test caching
        assertSame(subnet.toString(), subnet.toString());
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence) and valueOf(CharSequence, int, int)")
    DynamicTest[] testValueOfCIDRNotation() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertThrows(NullPointerException.class, () -> Subnet.valueOf(null));
                    assertThrows(NullPointerException.class, () -> Subnet.valueOf(null, 0, 0));
                }),
                testValueOfCIDRNotationInvalidRoutingPrefix("127.0.0.1/0", "127.0.0.1", 0),
                testValueOfCIDRNotation("127.0.0.1/32", 32, IPv4Address.LOCALHOST, IPv4Address.LOCALHOST),
                testValueOfCIDRNotation("0.0.0.0/0", 0, IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE),
                testValueOfCIDRNotation("192.0.0.0/8", 8, IPv4Address.valueOf(192, 0, 0, 0), IPv4Address.valueOf(192, 255, 255, 255)),
                testValueOfCIDRNotation("192.168.0.0/16", 16, IPv4Address.valueOf(192, 168, 0, 0), IPv4Address.valueOf(192, 168, 255, 255)),
                testValueOfCIDRNotation("192.168.171.0/24", 24, IPv4Address.valueOf(192, 168, 171, 0), IPv4Address.valueOf(192, 168, 171, 255)),
                testValueOfCIDRNotation("192.168.171.13/32", 32, IPv4Address.valueOf(192, 168, 171, 13), IPv4Address.valueOf(192, 168, 171, 13)),
                testValueOfCIDRNotationInvalidRoutingPrefix("192.168.171.13/8", "192.168.171.13", 8),
                testValueOfCIDRNotationInvalidRoutingPrefix("192.168.171.13/16", "192.168.171.13", 16),
                testValueOfCIDRNotationInvalidRoutingPrefix("192.168.171.13/24", "192.168.171.13", 24),
                testValueOfCIDRNotationInvalidPrefixLength(-1),
                testValueOfCIDRNotationInvalidPrefixLength(33),
                testValueOfCIDRNotationInvalidFormat("127.0.0.1"),
                testValueOfCIDRNotationInvalidFormat("127.0.0.1/x"),
                testValueOfCIDRNotationInvalidFormat("127.0.0/12"),

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
        };
    }

    private DynamicTest testValueOfCIDRNotation(CharSequence cidrNotation, int expectedPrefixLength,
            IPAddress<?> expectedFrom, IPAddress<?> expectedTo) {

        return dynamicTest(cidrNotation.toString(), () -> {
            Subnet<?> subnet = Subnet.valueOf(cidrNotation);
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            subnet = Subnet.valueOf("1" + cidrNotation + "1", 1, 1 + cidrNotation.length());
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidFormat(CharSequence cidrNotation) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidCIDRNotation.get(cidrNotation), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidRoutingPrefix(CharSequence cidrNotation, String routingPrefix, int prefixLength) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(routingPrefix, prefixLength), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Subnet.valueOf("127.0.0.1/" + prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("tryValueOf")
    DynamicTest[] testTryValueOf() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(Optional.empty(), Subnet.tryValueOf(null));
                    assertEquals(Optional.empty(), Subnet.tryValueOf(null, 0, 0));
                }),
                testTryValueOf("", Optional.empty()),
                testTryValueOf("127.0.0.1/0", Optional.empty()),
                testTryValueOf("127.0.0.1/32", Optional.of(Subnet.valueOf(IPv4Address.LOCALHOST, 32))),
                testTryValueOf("0.0.0.0/0", Optional.of(Subnet.valueOf(IPv4Address.MIN_VALUE, 0))),
                testTryValueOf("192.0.0.0/8", Optional.of(Subnet.valueOf(IPv4Address.valueOf(192, 0, 0, 0), 8))),
                testTryValueOf("192.168.0.0/16", Optional.of(Subnet.valueOf(IPv4Address.valueOf(192, 168, 0, 0), 16))),
                testTryValueOf("192.168.171.0/24", Optional.of(Subnet.valueOf(IPv4Address.valueOf(192, 168, 171, 0), 24))),
                testTryValueOf("192.168.171.13/32", Optional.of(Subnet.valueOf(IPv4Address.valueOf(192, 168, 171, 13), 32))),
                testTryValueOf("192.168.171.13/8", Optional.empty()),
                testTryValueOf("192.168.171.13/16", Optional.empty()),
                testTryValueOf("192.168.171.13/24", Optional.empty()),
                testTryValueOf("127.0.0.1/-1", Optional.empty()),
                testTryValueOf("127.0.0.1/33", Optional.empty()),
                testTryValueOf("127.0.0.1", Optional.empty()),
                testTryValueOf("127.0.0.1/x", Optional.empty()),
                testTryValueOf("127.0.0/12", Optional.empty()),

                testTryValueOf("::1/0", Optional.empty()),
                testTryValueOf("::1/128", Optional.of(Subnet.valueOf(IPv6Address.LOCALHOST, 128))),
                testTryValueOf("::/0", Optional.of(Subnet.valueOf(IPv6Address.MIN_VALUE, 0))),
                testTryValueOf("12::/16", Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0000_0000_0000L, 0L), 16))),
                testTryValueOf("12:34::/32", Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0000_0000L, 0L), 32))),
                testTryValueOf("12:34:56::/48", Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0000L, 0L), 48))),
                testTryValueOf("12:34:56:78::/64", Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0L), 64))),
                testTryValueOf("12:34:56:78:90::/80",
                        Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_0000_0000_0000L), 80))),
                testTryValueOf("12:34:56:78:90:ab::/96",
                        Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_0000_0000L), 96))),
                testTryValueOf("12:34:56:78:90:ab:cd::/112",
                        Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_0000L), 112))),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/128",
                        Optional.of(Subnet.valueOf(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0X0090_00AB_00CD_00EFL), 128))),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/16", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/32", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/48", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/64", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/80", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/96", Optional.empty()),
                testTryValueOf("12:34:56:78:90:ab:cd:ef/112", Optional.empty()),
                testTryValueOf("::1/-1", Optional.empty()),
                testTryValueOf("::1/129", Optional.empty()),
                testTryValueOf("::", Optional.empty()),
                testTryValueOf("::/x", Optional.empty()),
                testTryValueOf("::1::/x", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOf(String cidrNotation, Optional<Subnet<?>> expected) {
        String displayName = String.valueOf(cidrNotation);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, Subnet.tryValueOf(cidrNotation));
            assertEquals(expected, Subnet.tryValueOf("1" + cidrNotation + "1", 1, 1 + cidrNotation.length()));
            assertEquals(expected, Subnet.tryValueOf("z" + cidrNotation + "z", 1, 1 + cidrNotation.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.tryValueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.tryValueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.tryValueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.tryValueOf(cidrNotation, 0, -1));
        });
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence, int) and valueOf(IPAddress, int)")
    DynamicTest[] testValueOfWithIPAddress() {
        CharSequence address = "192.168.171.13";
        return new DynamicTest[] {
                dynamicTest("null CharSequence", () -> assertThrows(NullPointerException.class, () -> Subnet.valueOf((CharSequence) null, 1))),
                dynamicTest("null IPAddress", () -> assertThrows(NullPointerException.class, () -> Subnet.valueOf((IPAddress<?>) null, 1))),
                testValueOfWithIPAddressInvalidRoutingPrefix("127.0.0.1", 0),
                testValueOfWithIPAddress("127.0.0.1", 32, IPv4Address.LOCALHOST),
                testValueOfWithIPAddress("0.0.0.0", 0, IPv4Address.MAX_VALUE),
                testValueOfWithIPAddress("192.0.0.0", 8, IPv4Address.valueOf(192, 255, 255, 255)),
                testValueOfWithIPAddress("192.168.0.0", 16, IPv4Address.valueOf(192, 168, 255, 255)),
                testValueOfWithIPAddress("192.168.171.0", 24, IPv4Address.valueOf(192, 168, 171, 255)),
                testValueOfWithIPAddress("192.168.171.13", 32, IPv4Address.valueOf(192, 168, 171, 13)),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 8),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 16),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, 24),
                testValueOfWithIPAddressInvalidPrefixLength(-1),
                testValueOfWithIPAddressInvalidPrefixLength(33),
        };
    }

    private DynamicTest testValueOfWithIPAddress(CharSequence address, int prefixLength, IPAddress<?> expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPAddress<?> expectedFrom = IPAddress.valueOf(address);
            Subnet<?> subnet = Subnet.valueOf(address, prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidRoutingPrefix(CharSequence address, int prefixLength) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Subnet.valueOf(address, prefixLength));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Subnet.valueOf("127.0.0.1", prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("isSubnet")
    DynamicTest[] testIsSubnet() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(false, Subnet.isSubnet(null));
                    assertEquals(false, Subnet.isSubnet(null, 0, 0));
                }),
                testIsSubnet("", false),
                testIsSubnet("127.0.0.1/0", false),
                testIsSubnet("127.0.0.1/32", true),
                testIsSubnet("0.0.0.0/0", true),
                testIsSubnet("192.0.0.0/8", true),
                testIsSubnet("192.168.0.0/16", true),
                testIsSubnet("192.168.171.0/24", true),
                testIsSubnet("192.168.171.13/32", true),
                testIsSubnet("192.168.171.13/8", false),
                testIsSubnet("192.168.171.13/16", false),
                testIsSubnet("192.168.171.13/24", false),
                testIsSubnet("0.0.0.0/-1", false),
                testIsSubnet("0.0.0.0/33", false),
                testIsSubnet("127.0.0.1", false),
                testIsSubnet("127.0.0.1/x", false),
                testIsSubnet("127.0.0/12", false),

                testIsSubnet("::1/0", false),
                testIsSubnet("::1/128", true),
                testIsSubnet("::/0", true),
                testIsSubnet("12::/16", true),
                testIsSubnet("12:34::/32", true),
                testIsSubnet("12:34:56::/48", true),
                testIsSubnet("12:34:56:78::/64", true),
                testIsSubnet("12:34:56:78:90::/80", true),
                testIsSubnet("12:34:56:78:90:ab::/96", true),
                testIsSubnet("12:34:56:78:90:ab:cd::/112", true),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/128", true),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/16", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/32", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/48", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/64", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/80", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/96", false),
                testIsSubnet("12:34:56:78:90:ab:cd:ef/112", false),
                testIsSubnet("::/-1", false),
                testIsSubnet("::/129", false),
                testIsSubnet("::", false),
                testIsSubnet("::/x", false),
                testIsSubnet("::1::/x", false),
                testIsSubnet("127.0.0.1/12", false),
        };
    }

    private DynamicTest testIsSubnet(CharSequence s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, Subnet.isSubnet(s));
            assertEquals(expected, Subnet.isSubnet("1" + s + "1", 1, 1 + s.length()));
            assertEquals(expected, Subnet.isSubnet("z" + s + "z", 1, 1 + s.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.isSubnet(s, -1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.isSubnet(s, 0, s.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.isSubnet(s, s.length() + 1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> Subnet.isSubnet(s, 0, -1));
        });
    }

    private static final class TestSubnet extends Subnet<IPv4Address> {

        private TestSubnet(IPv4Address address) {
            super(address, address, IPv4Address.BITS);
        }

        @Override
        public int size() {
            return 0;
        }
    }
}
