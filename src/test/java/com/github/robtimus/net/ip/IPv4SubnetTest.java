/*
 * IPv4SubnetTest.java
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
class IPv4SubnetTest {

    @ParameterizedTest(name = "{0}/{1}: {2}")
    @MethodSource
    @DisplayName("size")
    void testSize(IPv4Address address, int prefixLength, int expectedSize) {
        IPv4Subnet subnet = address.startingSubnet(prefixLength);
        assertEquals(expectedSize, subnet.size());
        assertEquals(expectedSize, subnet.size());
    }

    static Arguments[] testSize() {
        IPv4Address address = IPv4Address.MIN_VALUE;
        return new Arguments[] {
                arguments(address, 0, Integer.MAX_VALUE),
                arguments(address, 1, Integer.MAX_VALUE),
                arguments(address, 2, 1073741824),
                arguments(address, 3, 536870912),
                arguments(address, 4, 268435456),
                arguments(address, 8, 16777216),
                arguments(address, 16, 65536),
                arguments(address, 24, 256),
                arguments(address, 30, 4),
                arguments(address, 31, 2),
                arguments(address, 32, 1),
        };
    }

    @Test
    @DisplayName("spliterator")
    void testSpliterator() {
        IPv4Subnet subnet = IPv4Address.MIN_VALUE.startingSubnet(0);
        Spliterator<?> spliterator = subnet.spliterator();
        // IPv4RangeSpliterator has its own tests
        assertEquals(IPv4RangeSpliterator.class, spliterator.getClass());
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence) and valueOf(CharSequence, int, int)")
    DynamicTest[] testValueOfCIDRNotation() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf(null));
                    assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf(null, 0, 0));
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
                testValueOfCIDRNotationInvalidFormat("::/12"),
        };
    }

    private DynamicTest testValueOfCIDRNotation(CharSequence cidrNotation, int expectedPrefixLength,
            IPv4Address expectedFrom, IPv4Address expectedTo) {

        return dynamicTest(cidrNotation.toString(), () -> {
            IPv4Subnet subnet = IPv4Subnet.valueOf(cidrNotation);
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            subnet = IPv4Subnet.valueOf("1" + cidrNotation + "1", 1, 1 + cidrNotation.length());
            assertEquals(expectedPrefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidFormat(CharSequence cidrNotation) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidCIDRNotation.get(cidrNotation), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidRoutingPrefix(CharSequence cidrNotation, String routingPrefix, int prefixLength) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(routingPrefix, prefixLength), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.valueOf(cidrNotation, 0, -1));
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf("127.0.0.1/" + prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("tryValueOfIPv4")
    DynamicTest[] testTryValueOfIPv4() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(Optional.empty(), IPv4Subnet.tryValueOfIPv4(null));
                    assertEquals(Optional.empty(), IPv4Subnet.tryValueOfIPv4(null, 0, 0));
                }),
                testTryValueOfIPv4("", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1/0", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1/32", Optional.of(IPv4Subnet.valueOf(IPv4Address.LOCALHOST, 32))),
                testTryValueOfIPv4("0.0.0.0/0", Optional.of(IPv4Subnet.valueOf(IPv4Address.MIN_VALUE, 0))),
                testTryValueOfIPv4("192.0.0.0/8", Optional.of(IPv4Subnet.valueOf(IPv4Address.valueOf(192, 0, 0, 0), 8))),
                testTryValueOfIPv4("192.168.0.0/16", Optional.of(IPv4Subnet.valueOf(IPv4Address.valueOf(192, 168, 0, 0), 16))),
                testTryValueOfIPv4("192.168.171.0/24", Optional.of(IPv4Subnet.valueOf(IPv4Address.valueOf(192, 168, 171, 0), 24))),
                testTryValueOfIPv4("192.168.171.13/32", Optional.of(IPv4Subnet.valueOf(IPv4Address.valueOf(192, 168, 171, 13), 32))),
                testTryValueOfIPv4("192.168.171.13/8", Optional.empty()),
                testTryValueOfIPv4("192.168.171.13/16", Optional.empty()),
                testTryValueOfIPv4("192.168.171.13/24", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1/-1", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1/33", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1", Optional.empty()),
                testTryValueOfIPv4("127.0.0.1/x", Optional.empty()),
                testTryValueOfIPv4("127.0.0/12", Optional.empty()),
                testTryValueOfIPv4("::/12", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOfIPv4(String cidrNotation, Optional<IPv4Subnet> expected) {
        String displayName = String.valueOf(cidrNotation);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, IPv4Subnet.tryValueOfIPv4(cidrNotation));
            assertEquals(expected, IPv4Subnet.tryValueOfIPv4("1" + cidrNotation + "1", 1, 1 + cidrNotation.length()));
            assertEquals(expected, IPv4Subnet.tryValueOfIPv4("z" + cidrNotation + "z", 1, 1 + cidrNotation.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.tryValueOfIPv4(cidrNotation, -1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.tryValueOfIPv4(cidrNotation, 0, cidrNotation.length() + 1));
            assertThrows(IndexOutOfBoundsException.class,
                    () -> IPv4Subnet.tryValueOfIPv4(cidrNotation, cidrNotation.length() + 1, cidrNotation.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.tryValueOfIPv4(cidrNotation, 0, -1));
        });
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence, int) and valueOf(IPv4Address, int)")
    DynamicTest[] testValueOfWithIPAddress() {
        CharSequence address = "192.168.171.13";
        return new DynamicTest[] {
                dynamicTest("null CharSequence", () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf((CharSequence) null, 1))),
                dynamicTest("null IPAddress", () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf((IPv4Address) null, 1))),
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

    private DynamicTest testValueOfWithIPAddress(CharSequence address, int prefixLength, IPv4Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv4Address expectedFrom = IPv4Address.valueOf(address);
            IPv4Subnet subnet = IPv4Subnet.valueOf(address, prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidRoutingPrefix(CharSequence address, int prefixLength) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf(address, prefixLength));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf("127.0.0.1", prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence, Charsequence) and valueOf(IPv4Address, IPv4Address)")
    DynamicTest[] testValueOfWithIPAddressWithNetmask() {
        CharSequence address = "192.168.171.13";
        return new DynamicTest[] {
                dynamicTest("null CharSequence", () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf(null, "0.0.0.0"))),
                dynamicTest("null IPAddress",
                        () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf(null, IPv4Address.getNetmask(0)))),
                dynamicTest("null CharSequence netmask", () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf("0.0.0.0", null))),
                dynamicTest("null IPAddress netmask",
                        () -> assertThrows(NullPointerException.class, () -> IPv4Subnet.valueOf(IPv4Address.MIN_VALUE, null))),
                testValueOfWithIPAddressInvalidRoutingPrefix("127.0.0.1", "0.0.0.0", 0),
                testValueOfWithIPAddress("127.0.0.1", "255.255.255.255", 32, IPv4Address.LOCALHOST),
                testValueOfWithIPAddress("0.0.0.0", "0.0.0.0", 0, IPv4Address.MAX_VALUE),
                testValueOfWithIPAddress("192.0.0.0", "255.0.0.0", 8, IPv4Address.valueOf(192, 255, 255, 255)),
                testValueOfWithIPAddress("192.168.0.0", "255.255.0.0", 16, IPv4Address.valueOf(192, 168, 255, 255)),
                testValueOfWithIPAddress("192.168.171.0", "255.255.255.0", 24, IPv4Address.valueOf(192, 168, 171, 255)),
                testValueOfWithIPAddress("192.168.171.13", "255.255.255.255", 32, IPv4Address.valueOf(192, 168, 171, 13)),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, "255.0.0.0", 8),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, "255.255.0.0", 16),
                testValueOfWithIPAddressInvalidRoutingPrefix(address, "255.255.255.0", 24),
                testValueOfWithIPAddressInvalidNetmask("255.0.255.0"),
        };
    }

    private DynamicTest testValueOfWithIPAddress(CharSequence address, CharSequence netmask, int prefixLength, IPv4Address expectedTo) {
        return dynamicTest(String.format("%s/%s", address, netmask), () -> {
            IPv4Address expectedFrom = IPv4Address.valueOf(address);
            IPv4Subnet subnet = IPv4Subnet.valueOf(address, netmask);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidRoutingPrefix(CharSequence address, CharSequence netmask, int prefixLength) {
        return dynamicTest(String.format("%s/%s", address, netmask), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf(address, netmask));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidNetmask(CharSequence netmask) {
        return dynamicTest(String.format("invalid netmask: %s", netmask), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Subnet.valueOf("127.0.0.1", netmask));
            assertEquals(Messages.Subnet.invalidNetmask.get(netmask), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("isIPv4Subnet")
    DynamicTest[] testIsIPv4Subnet() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertEquals(false, IPv4Subnet.isIPv4Subnet(null));
                    assertEquals(false, IPv4Subnet.isIPv4Subnet(null, 0, 0));
                }),
                testIsIPv4Subnet("", false),
                testIsIPv4Subnet("127.0.0.1/0", false),
                testIsIPv4Subnet("127.0.0.1/32", true),
                testIsIPv4Subnet("0.0.0.0/0", true),
                testIsIPv4Subnet("192.0.0.0/8", true),
                testIsIPv4Subnet("192.168.0.0/16", true),
                testIsIPv4Subnet("192.168.171.0/24", true),
                testIsIPv4Subnet("192.168.171.13/32", true),
                testIsIPv4Subnet("192.168.171.13/8", false),
                testIsIPv4Subnet("192.168.171.13/16", false),
                testIsIPv4Subnet("192.168.171.13/24", false),
                testIsIPv4Subnet("0.0.0.0/-1", false),
                testIsIPv4Subnet("0.0.0.0/33", false),
                testIsIPv4Subnet("127.0.0.1", false),
                testIsIPv4Subnet("127.0.0.1/x", false),
                testIsIPv4Subnet("127.0.0/12", false),
                testIsIPv4Subnet("::/12", false),
        };
    }

    private DynamicTest testIsIPv4Subnet(CharSequence s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
            assertEquals(expected, IPv4Subnet.isIPv4Subnet(s));
            assertEquals(expected, IPv4Subnet.isIPv4Subnet("1" + s + "1", 1, 1 + s.length()));
            assertEquals(expected, IPv4Subnet.isIPv4Subnet("z" + s + "z", 1, 1 + s.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.isIPv4Subnet(s, -1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.isIPv4Subnet(s, 0, s.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.isIPv4Subnet(s, s.length() + 1, s.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Subnet.isIPv4Subnet(s, 0, -1));
        });
    }
}
