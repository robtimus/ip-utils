/*
 * IPv4AddressTest.java
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("nls")
class IPv4AddressTest {

    @Test
    @DisplayName("bits")
    void testBits() {
        assertEquals(32, IPv4Address.LOCALHOST.bits());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("toByteArray")
    void testToByteArray(IPv4Address address, byte[] expected) {
        assertArrayEquals(expected, address.toByteArray());
    }

    static Arguments[] testToByteArray() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, new byte[] { 127, 0, 0, 1 }),
                arguments(IPv4Address.MIN_VALUE, new byte[] { 0, 0, 0, 0 }),
                arguments(IPv4Address.MAX_VALUE, new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255 }),
                arguments(IPv4Address.valueOf(12, 34, 56, 78), new byte[] { 12, 34, 56, 78 }),
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("toInetAddress")
    void testToInetAddress(IPv4Address address, String expected) throws UnknownHostException {
        assertEquals(InetAddress.getByName(expected), address.toInetAddress());
        // test caching
        assertSame(address.toInetAddress(), address.toInetAddress());
    }

    static Arguments[] testToInetAddress() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, "127.0.0.1"),
                arguments(IPv4Address.MIN_VALUE, "0.0.0.0"),
                arguments(IPv4Address.MAX_VALUE, "255.255.255.255"),
                arguments(IPv4Address.valueOf(12, 34, 56, 78), "12.34.56.78"),
        };
    }

    @Test
    @DisplayName("toIPv6")
    void testToIPv6() {
        IPv4Address address = IPv4Address.valueOf(192, 168, 1, 13);
        IPv6Address result = address.toIPv6();
        assertEquals(IPv6Address.valueOf(0, 0x0000_FFFF_C0A8_010DL), result);
        assertEquals("::ffff:" + address, IPAddressFormatter.ipv6().withIPv4End().build().format(result));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("equals")
    void testEquals(IPv4Address address, Object object, boolean expectEquals) {
        BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        equalsCheck.accept(address, object);
    }

    static Arguments[] testEquals() {
        IPv4Address address = IPv4Address.valueOf(0x12, 0x34, 0x56, 0x78);
        return new Arguments[] {
                arguments(address, null, false),
                arguments(address, "foo", false),
                arguments(address, IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0x1234, 0x5678), false),
                arguments(address, address, true),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0x56, 0x78), true),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0x56, 0), false),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0, 0x78), false),
                arguments(address, IPv4Address.valueOf(0x12, 0, 0x56, 0x78), false),
                arguments(address, IPv4Address.valueOf(0, 0x34, 0x56, 0x78), false),
        };
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("hashCode")
    void testHashCode(IPv4Address address, IPv4Address other, boolean expectEquals) {
        BiConsumer<Integer, Integer> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        equalsCheck.accept(address.hashCode(), other.hashCode());
    }

    static Arguments[] testHashCode() {
        IPv4Address address = IPv4Address.valueOf(0x12, 0x34, 0x56, 0x78);
        return new Arguments[] {
                arguments(address, address, true),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0x56, 0x78), true),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0x56, 0), false),
                arguments(address, IPv4Address.valueOf(0x12, 0x34, 0, 0x78), false),
                arguments(address, IPv4Address.valueOf(0x12, 0, 0x56, 0x78), false),
                arguments(address, IPv4Address.valueOf(0, 0x34, 0x56, 0x78), false),
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("toString")
    void testToString(IPv4Address address, String expected) {
        assertEquals(expected, address.toString());
        // test caching
        assertSame(address.toString(), address.toString());
    }

    static Arguments[] testToString() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, "127.0.0.1"),
                arguments(IPv4Address.MIN_VALUE, "0.0.0.0"),
                arguments(IPv4Address.MAX_VALUE, "255.255.255.255"),
                arguments(IPv4Address.valueOf(12, 34, 56, 78), "12.34.56.78"),
        };
    }

    @TestFactory
    @DisplayName("compareTo")
    DynamicTest[] testCompareTo() {
        IPv4Address address = IPv4Address.valueOf(12, 34, 56, 78);
        return new DynamicTest[] {
                testCompareToEqual(IPv4Address.LOCALHOST, IPv4Address.LOCALHOST),
                testCompareToLarger(IPv4Address.LOCALHOST, IPv4Address.MIN_VALUE),
                testCompareToSmaller(IPv4Address.LOCALHOST, IPv4Address.MAX_VALUE),

                testCompareToEqual(address, address),
                testCompareToSmaller(address, IPv4Address.valueOf(12, 34, 56, 79)),
                testCompareToLarger(address, IPv4Address.valueOf(12, 34, 56, 77)),
                testCompareToSmaller(address, IPv4Address.valueOf(12, 34, 57, 78)),
                testCompareToLarger(address, IPv4Address.valueOf(12, 34, 55, 78)),
                testCompareToSmaller(address, IPv4Address.valueOf(12, 35, 56, 78)),
                testCompareToLarger(address, IPv4Address.valueOf(12, 33, 56, 78)),
                testCompareToSmaller(address, IPv4Address.valueOf(13, 34, 56, 78)),
                testCompareToLarger(address, IPv4Address.valueOf(11, 34, 56, 78)),
        };
    }

    private DynamicTest testCompareToEqual(IPv4Address address, IPv4Address other) {
        return dynamicTest(other.toString(), () -> assertEquals(0, address.compareTo(other)));
    }

    private DynamicTest testCompareToSmaller(IPv4Address address, IPv4Address other) {
        return dynamicTest(other.toString(), () -> assertTrue(address.compareTo(other) < 0));
    }

    private DynamicTest testCompareToLarger(IPv4Address address, IPv4Address other) {
        return dynamicTest(other.toString(), () -> assertTrue(address.compareTo(other) > 0));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isMulticastAddress")
    void testIsMulticastAddress(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isMulticastAddress());
    }

    static Arguments[] testIsMulticastAddress() {
        List<Arguments> arguments = new ArrayList<>();
        arguments.add(arguments(IPv4Address.LOCALHOST, false));
        arguments.add(arguments(IPv4Address.MIN_VALUE, false));
        arguments.add(arguments(IPv4Address.MAX_VALUE, false));
        arguments.add(arguments(IPv4Address.valueOf(223, 255, 255, 255), false));
        for (int octet = 224; octet <= 239; octet++) {
            arguments.add(arguments(IPv4Address.valueOf(octet, 0, 0, 0), true));
            arguments.add(arguments(IPv4Address.valueOf(octet, 255, 255, 255), true));
        }
        arguments.add(arguments(IPv4Address.valueOf(240, 0, 0, 0), false));
        return arguments.stream().toArray(Arguments[]::new);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isWildcardAddress")
    void testIsWildcardAddress(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isWildcardAddress());
    }

    static Arguments[] testIsWildcardAddress() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, false),
                arguments(IPv4Address.MIN_VALUE, true),
                arguments(IPv4Address.MAX_VALUE, false),
                arguments(IPv4Address.valueOf(0, 0, 0, 1), false),
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isLoopbackAddress")
    void testIsLoopbackAddress(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isLoopbackAddress());
    }

    static Arguments[] testIsLoopbackAddress() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, true),
                arguments(IPv4Address.MIN_VALUE, false),
                arguments(IPv4Address.MAX_VALUE, false),
                arguments(IPv4Address.valueOf(126, 255, 255, 255), false),
                arguments(IPv4Address.valueOf(127, 0, 0, 0), true),
                arguments(IPv4Address.valueOf(127, 255, 255, 255), true),
                arguments(IPv4Address.valueOf(128, 0, 0, 0), false),
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isLinkLocalAddress")
    void testIsLinkLocalAddress(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isLinkLocalAddress());
    }

    static Arguments[] testIsLinkLocalAddress() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, false),
                arguments(IPv4Address.MIN_VALUE, false),
                arguments(IPv4Address.MAX_VALUE, false),
                arguments(IPv4Address.valueOf(169, 253, 255, 255), false),
                arguments(IPv4Address.valueOf(169, 254, 0, 0), true),
                arguments(IPv4Address.valueOf(169, 254, 255, 255), true),
                arguments(IPv4Address.valueOf(169, 255, 0, 0), false),
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isSiteLocalAddress")
    void testIsSiteLocalAddress(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isSiteLocalAddress());
    }

    static Arguments[] testIsSiteLocalAddress() {
        List<Arguments> arguments = new ArrayList<>();
        arguments.add(arguments(IPv4Address.LOCALHOST, false));
        arguments.add(arguments(IPv4Address.MIN_VALUE, false));
        arguments.add(arguments(IPv4Address.MAX_VALUE, false));
        arguments.add(arguments(IPv4Address.valueOf(9, 255, 255, 255), false));
        arguments.add(arguments(IPv4Address.valueOf(10, 0, 0, 0), true));
        arguments.add(arguments(IPv4Address.valueOf(10, 255, 255, 255), true));
        arguments.add(arguments(IPv4Address.valueOf(11, 0, 0, 0), false));
        arguments.add(arguments(IPv4Address.valueOf(172, 15, 255, 255), false));
        for (int octet = 16; octet <= 31; octet++) {
            arguments.add(arguments(IPv4Address.valueOf(172, octet, 0, 0), true));
            arguments.add(arguments(IPv4Address.valueOf(172, octet, 255, 255), true));
        }
        arguments.add(arguments(IPv4Address.valueOf(172, 32, 0, 0), false));
        arguments.add(arguments(IPv4Address.valueOf(192, 167, 255, 255), false));
        arguments.add(arguments(IPv4Address.valueOf(192, 168, 0, 0), true));
        arguments.add(arguments(IPv4Address.valueOf(192, 168, 255, 255), true));
        arguments.add(arguments(IPv4Address.valueOf(192, 169, 0, 0), false));
        return arguments.stream().toArray(Arguments[]::new);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("hasNext")
    void testHasNext(IPv4Address address, boolean expected) {
        assertEquals(expected, address.hasNext());
    }

    static Arguments[] testHasNext() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, true),
                arguments(IPv4Address.MIN_VALUE, true),
                arguments(IPv4Address.MAX_VALUE, false),
                arguments(IPv4Address.valueOf(255, 255, 255, 254), true),
        };
    }

    @TestFactory
    @DisplayName("next")
    DynamicTest[] testNext() {
        return new DynamicTest[] {
                testNext(IPv4Address.LOCALHOST, IPv4Address.valueOf(127, 0, 0, 2)),
                testNext(IPv4Address.MIN_VALUE, IPv4Address.valueOf(0, 0, 0, 1)),
                testNext(IPv4Address.valueOf(12, 34, 56, 78), IPv4Address.valueOf(12, 34, 56, 79)),
                testNext(IPv4Address.valueOf(255, 255, 255, 254), IPv4Address.MAX_VALUE),
                dynamicTest(IPv4Address.MAX_VALUE.toString(), () -> assertThrows(NoSuchElementException.class, IPv4Address.MAX_VALUE::next)),
        };
    }

    private DynamicTest testNext(IPv4Address address, IPv4Address expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.next()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("hasPrevious")
    void testHasPrevious(IPv4Address address, boolean expected) {
        assertEquals(expected, address.hasPrevious());
    }

    static Arguments[] testHasPrevious() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, true),
                arguments(IPv4Address.MIN_VALUE, false),
                arguments(IPv4Address.MAX_VALUE, true),
                arguments(IPv4Address.valueOf(0, 0, 0, 1), true),
        };
    }

    @TestFactory
    @DisplayName("previous")
    DynamicTest[] testPrevious() {
        return new DynamicTest[] {
                testPrevious(IPv4Address.LOCALHOST, IPv4Address.valueOf(127, 0, 0, 0)),
                testPrevious(IPv4Address.MAX_VALUE, IPv4Address.valueOf(255, 255, 255, 254)),
                testPrevious(IPv4Address.valueOf(12, 34, 56, 78), IPv4Address.valueOf(12, 34, 56, 77)),
                testPrevious(IPv4Address.valueOf(0, 0, 0, 1), IPv4Address.MIN_VALUE),
                dynamicTest(IPv4Address.MIN_VALUE.toString(), () -> assertThrows(NoSuchElementException.class, IPv4Address.MIN_VALUE::previous)),
        };
    }

    private DynamicTest testPrevious(IPv4Address address, IPv4Address expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.previous()));
    }

    @ParameterizedTest(name = "{0}.mid({1})")
    @MethodSource
    @DisplayName("mid")
    void testMid(IPv4Address low, IPv4Address high, IPv4Address expected) {
        assertEquals(expected, low.mid(high));
    }

    static Arguments[] testMid() {
        return new Arguments[] {
                arguments(IPv4Address.LOCALHOST, IPv4Address.LOCALHOST, IPv4Address.LOCALHOST),
                arguments(IPv4Address.LOCALHOST, IPv4Address.LOCALHOST.next(), IPv4Address.LOCALHOST),
                arguments(IPv4Address.LOCALHOST.previous(), IPv4Address.LOCALHOST.next(), IPv4Address.LOCALHOST),
                arguments(IPv4Address.MIN_VALUE, IPv4Address.MIN_VALUE, IPv4Address.MIN_VALUE),
                arguments(IPv4Address.MIN_VALUE, IPv4Address.MIN_VALUE.next(), IPv4Address.MIN_VALUE),
                arguments(IPv4Address.MAX_VALUE, IPv4Address.MAX_VALUE, IPv4Address.MAX_VALUE),
                arguments(IPv4Address.MAX_VALUE.previous(), IPv4Address.MAX_VALUE, IPv4Address.MAX_VALUE.previous()),
                arguments(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE, IPv4Address.valueOf(Integer.MAX_VALUE)),
        };
    }

    @TestFactory
    @DisplayName("to")
    DynamicTest[] testTo() {
        // Don't test the range itself, only its to and from values. The range has its own tests.
        return new DynamicTest[] {
                dynamicTest("MIN_VALUE to MAX_VALUE", () -> {
                    IPv4Range range = IPv4Address.MIN_VALUE.to(IPv4Address.MAX_VALUE);
                    assertEquals(IPv4Address.MIN_VALUE, range.from());
                    assertEquals(IPv4Address.MAX_VALUE, range.to());
                    assertEquals(IPRangeImpl.IPv4.class, range.getClass());
                }),
                dynamicTest("MIN_VALUE to MIN_VALUE", () -> {
                    IPv4Range range = IPv4Address.MIN_VALUE.to(IPv4Address.MIN_VALUE);
                    assertEquals(IPv4Address.MIN_VALUE, range.from());
                    assertEquals(IPv4Address.MIN_VALUE, range.to());
                    assertEquals(SingletonIPRange.IPv4.class, range.getClass());
                }),
                dynamicTest("MAX_VALUE to MIN_VALUE", () -> {
                    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                            () -> IPv4Address.MAX_VALUE.to(IPv4Address.MIN_VALUE));
                    assertEquals(Messages.IPRange.toSmallerThanFrom.get(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE), exception.getMessage());
                }),
        };
    }

    @Test
    @DisplayName("asRange")
    void testAsRange() {
        // Don't test the range itself, only its to and from values. The range has its own tests.
        IPv4Range range = IPv4Address.MIN_VALUE.asRange();
        assertEquals(IPv4Address.MIN_VALUE, range.from());
        assertEquals(IPv4Address.MIN_VALUE, range.to());
        assertEquals(SingletonIPRange.IPv4.class, range.getClass());
    }

    @TestFactory
    @DisplayName("inSubnet")
    DynamicTest[] testInSubnet() {
        IPv4Address address = IPv4Address.valueOf(192, 168, 171, 13);
        return new DynamicTest[] {
                testInSubnet(IPv4Address.LOCALHOST, 0, IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE),
                testInSubnet(IPv4Address.LOCALHOST, 32, IPv4Address.LOCALHOST, IPv4Address.LOCALHOST),
                testInSubnet(address, 0, IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE),
                testInSubnet(address, 8, IPv4Address.valueOf(192, 0, 0, 0), IPv4Address.valueOf(192, 255, 255, 255)),
                testInSubnet(address, 16, IPv4Address.valueOf(192, 168, 0, 0), IPv4Address.valueOf(192, 168, 255, 255)),
                testInSubnet(address, 24, IPv4Address.valueOf(192, 168, 171, 0), IPv4Address.valueOf(192, 168, 171, 255)),
                testInSubnet(address, 32, address, address),
                testInSubnetInvalidPrefixLength(-1),
                testInSubnetInvalidPrefixLength(33),
        };
    }

    private DynamicTest testInSubnet(IPv4Address address, int prefixLength, IPv4Address expectedFrom, IPv4Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv4Subnet subnet = address.inSubnet(prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testInSubnetInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Address.LOCALHOST.inSubnet(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("startingSubnet(int)")
    DynamicTest[] testStartingSubnet() {
        IPv4Address address = IPv4Address.valueOf(192, 168, 171, 13);
        return new DynamicTest[] {
                testStartingSubnetInvalidRoutingPrefix(IPv4Address.LOCALHOST, 0),
                testStartingSubnet(IPv4Address.LOCALHOST, 32, IPv4Address.LOCALHOST),
                testStartingSubnet(IPv4Address.MIN_VALUE, 0, IPv4Address.MAX_VALUE),
                testStartingSubnet(IPv4Address.valueOf(192, 0, 0, 0), 8, IPv4Address.valueOf(192, 255, 255, 255)),
                testStartingSubnet(IPv4Address.valueOf(192, 168, 0, 0), 16, IPv4Address.valueOf(192, 168, 255, 255)),
                testStartingSubnet(IPv4Address.valueOf(192, 168, 171, 0), 24, IPv4Address.valueOf(192, 168, 171, 255)),
                testStartingSubnet(address, 32, address),
                testStartingSubnetInvalidRoutingPrefix(address, 8),
                testStartingSubnetInvalidRoutingPrefix(address, 16),
                testStartingSubnetInvalidRoutingPrefix(address, 24),
                testStartingSubnetInvalidPrefixLength(-1),
                testStartingSubnetInvalidPrefixLength(33),
        };
    }

    private DynamicTest testStartingSubnet(IPv4Address address, int prefixLength, IPv4Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv4Subnet subnet = address.startingSubnet(prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertSame(address, subnet.routingPrefix());
            assertSame(address, subnet.from());
            assertEquals(expectedTo, subnet.to());
            if (expectedTo.equals(address)) {
                assertSame(address, subnet.to());
            }
        });
    }

    private DynamicTest testStartingSubnetInvalidRoutingPrefix(IPv4Address address, int prefixLength) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> address.startingSubnet(prefixLength));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testStartingSubnetInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> IPv4Address.MIN_VALUE.startingSubnet(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("startingSubnet(IPv4Address)")
    DynamicTest[] testStartingSubnetWithIPv4Address() {
        return new DynamicTest[] {
                testStartingSubnet(IPv4Address.LOCALHOST, IPv4Address.MAX_VALUE, IPv4Address.LOCALHOST),
                testStartingSubnet(IPv4Address.MIN_VALUE, IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE),
                testStartingSubnet(IPv4Address.valueOf(192, 0, 0, 0), IPv4Address.getNetmask(8), IPv4Address.valueOf(192, 255, 255, 255)),
                testStartingSubnet(IPv4Address.valueOf(192, 168, 0, 0), IPv4Address.getNetmask(16), IPv4Address.valueOf(192, 168, 255, 255)),
                testStartingSubnet(IPv4Address.valueOf(192, 168, 171, 0), IPv4Address.getNetmask(24), IPv4Address.valueOf(192, 168, 171, 255)),
                testStartingSubnet(IPv4Address.valueOf(192, 168, 171, 13), IPv4Address.getNetmask(32), IPv4Address.valueOf(192, 168, 171, 13)),
                testStartingSubnetInvalidNetmask(IPv4Address.valueOf(255, 255, 255, 253)),
        };
    }

    private DynamicTest testStartingSubnet(IPv4Address address, IPv4Address netmask, IPv4Address expectedTo) {
        return dynamicTest(String.format("%s/%s", address, netmask), () -> {
            IPv4Subnet subnet = address.startingSubnet(netmask);
            assertSame(address, subnet.routingPrefix());
            assertSame(address, subnet.from());
            assertEquals(expectedTo, subnet.to());
            if (expectedTo.equals(address)) {
                assertSame(address, subnet.to());
            }
        });
    }

    private DynamicTest testStartingSubnetInvalidNetmask(IPv4Address netmask) {
        return dynamicTest(String.format("invalid netmask: %s", netmask), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Address.MIN_VALUE.startingSubnet(netmask));
            assertEquals(Messages.Subnet.invalidNetmask.get(netmask), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("valueOf(int, int, int, int)")
    DynamicTest[] testValueOfOctets() {
        return new DynamicTest[] {
                testValueOfOctets(0x12, 0x34, 0x56, 0x78, IPv4Address.valueOf(0x12345678)),
                testValueOfOctets(0, 0, 0, 0, IPv4Address.MIN_VALUE),
                testValueOfOctets(255, 255, 255, 255, IPv4Address.MAX_VALUE),
                testValueOfInvalidOctets(0, 0, 0, -1, -1),
                testValueOfInvalidOctets(0, 0, 0, 256, 256),
                testValueOfInvalidOctets(0, 0, -1, 0, -1),
                testValueOfInvalidOctets(0, 0, 256, 0, 256),
                testValueOfInvalidOctets(0, -1, 0, 0, -1),
                testValueOfInvalidOctets(0, 256, 0, 0, 256),
                testValueOfInvalidOctets(-1, 0, 0, 0, -1),
                testValueOfInvalidOctets(256, 0, 0, 0, 256),
        };
    }

    private DynamicTest testValueOfOctets(int octet1, int octet2, int octet3, int octet4, IPv4Address expected) {
        return dynamicTest(String.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4),
                () -> assertEquals(expected, IPv4Address.valueOf(octet1, octet2, octet3, octet4)));
    }

    private DynamicTest testValueOfInvalidOctets(int octet1, int octet2, int octet3, int octet4, int firstInvalidOctet) {
        return dynamicTest(String.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> IPv4Address.valueOf(octet1, octet2, octet3, octet4));
            assertEquals(Messages.IPv4Address.invalidOctet.get(firstInvalidOctet), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("valueOf(byte[])")
    DynamicTest[] testValueOfByteArray() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPv4Address.valueOf((byte[]) null))),
                testValueOfByteArray(new byte[] { 0x12, 0x34, 0x56, 0x78 }, IPv4Address.valueOf(0x12345678)),
                testValueOfByteArray(new byte[] { 0, 0, 0, 0 }, IPv4Address.MIN_VALUE),
                testValueOfByteArray(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255 }, IPv4Address.MAX_VALUE),
                testValueOfByteArrayOfInvalidSize(new byte[0]),
                testValueOfByteArrayOfInvalidSize(new byte[3]),
                testValueOfByteArrayOfInvalidSize(new byte[5]),
                testValueOfByteArrayOfInvalidSize(new byte[16]),
        };
    }

    private DynamicTest testValueOfByteArray(byte[] address, IPv4Address expected) {
        return dynamicTest(Arrays.toString(address), () -> assertEquals(expected, IPv4Address.valueOf(address)));
    }

    private DynamicTest testValueOfByteArrayOfInvalidSize(byte[] address) {
        return dynamicTest(Arrays.toString(address), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Address.valueOf(address));
            assertEquals(Messages.IPAddress.invalidArraySize.get(address.length), exception.getMessage());
        });
    }

    @TestFactory
    @DisplayName("valueOf(CharSequence) and valueOf(CharSequence, int, int)")
    DynamicTest[] testValueOfCharSequence() {
        return new DynamicTest[] {
                dynamicTest("null", () -> {
                    assertThrows(NullPointerException.class, () -> IPv4Address.valueOf((CharSequence) null));
                    assertThrows(NullPointerException.class, () -> IPv4Address.valueOf((CharSequence) null, 0, 0));
                }),
                testValueOfCharSequence("127.0.0.1", IPv4Address.LOCALHOST),
                testValueOfCharSequence("0.0.0.0", IPv4Address.MIN_VALUE),
                testValueOfCharSequence("255.255.255.255", IPv4Address.MAX_VALUE),
                testValueOfCharSequence("12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                // Just two invalid cases. The parsing has its own tests.
                testValueOfInvalidCharSequence("123.456.789.0"),
                testValueOfInvalidCharSequence("12.34.56.789"),
        };
    }

    private DynamicTest testValueOfCharSequence(String address, IPv4Address expected) {
        return dynamicTest(address, () -> {
            assertEquals(expected, IPv4Address.valueOf(address));
            assertEquals(expected, IPv4Address.valueOf("1" + address + "1", 1, 1 + address.length()));
            assertEquals(expected, IPv4Address.valueOf("z" + address + "z", 1, 1 + address.length()));

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, -1, address.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, 0, address.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, address.length() + 1, address.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, 0, -1));
        });
    }

    private DynamicTest testValueOfInvalidCharSequence(String address) {
        return dynamicTest(address, () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Address.valueOf(address));
            assertEquals(Messages.IPAddress.invalidIPAddress.get(address), exception.getMessage());

            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, -1, address.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, 0, address.length() + 1));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, address.length() + 1, address.length()));
            assertThrows(IndexOutOfBoundsException.class, () -> IPv4Address.valueOf(address, 0, -1));
        });
    }

    @TestFactory
    @DisplayName("tryValueOf")
    DynamicTest[] testTryValueOf() {
        return new DynamicTest[] {
                testTryValueOf(null, Optional.empty()),
                testTryValueOf("", Optional.empty()),
                testTryValueOf("127.0.0.1", Optional.of(IPv4Address.LOCALHOST)),
                testTryValueOf("0.0.0.0", Optional.of(IPv4Address.MIN_VALUE)),
                testTryValueOf("255.255.255.255", Optional.of(IPv4Address.MAX_VALUE)),
                testTryValueOf("12.34.56.78", Optional.of(IPv4Address.valueOf(12, 34, 56, 78))),
                testTryValueOf("::1", Optional.empty()),
                testTryValueOf("::", Optional.empty()),
                // Just four invalid cases. The parsing has its own tests.
                testTryValueOf("123.456.789.0", Optional.empty()),
                testTryValueOf("12.34.56.789", Optional.empty()),
                testTryValueOf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Optional.empty()),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef12", Optional.empty()),
                testTryValueOf("1234:5678:90ab::cdef", Optional.empty()),
                testTryValueOf("::192.168.0.1", Optional.empty()),
                testTryValueOf("12345:6789:0abc:def3:4567:890a:bcde:f123", Optional.empty()),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef123", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOf(String address, Optional<IPv4Address> expected) {
        String displayName = String.valueOf(address);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv4Address.tryValueOfIPv4(address)));
    }

    @TestFactory
    @DisplayName("valueOf(Inet4Address)")
    DynamicTest[] testValueOfInetAddress() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPAddress.valueOf((InetAddress) null))),
                testValueOfInetAddress("127.0.0.1", IPv4Address.LOCALHOST),
                testValueOfInetAddress("0.0.0.0", IPv4Address.MIN_VALUE),
                testValueOfInetAddress("255.255.255.255", IPv4Address.MAX_VALUE),
                testValueOfInetAddress("12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
        };
    }

    private DynamicTest testValueOfInetAddress(String address, IPv4Address expected) {
        return dynamicTest(address, () -> assertEquals(expected, IPv4Address.valueOf((Inet4Address) InetAddress.getByName(address))));
    }

    @TestFactory
    @DisplayName("getNetmask")
    DynamicTest[] testGetNetmask() {
        return new DynamicTest[] {
                testGetNetmask(0, 0b00000000_00000000_00000000_00000000),
                testGetNetmask(1, 0b10000000_00000000_00000000_00000000),
                testGetNetmask(2, 0b11000000_00000000_00000000_00000000),
                testGetNetmask(3, 0b11100000_00000000_00000000_00000000),
                testGetNetmask(4, 0b11110000_00000000_00000000_00000000),
                testGetNetmask(5, 0b11111000_00000000_00000000_00000000),
                testGetNetmask(6, 0b11111100_00000000_00000000_00000000),
                testGetNetmask(7, 0b11111110_00000000_00000000_00000000),
                testGetNetmask(8, 0b11111111_00000000_00000000_00000000),
                testGetNetmask(9, 0b11111111_10000000_00000000_00000000),
                testGetNetmask(10, 0b11111111_11000000_00000000_00000000),
                testGetNetmask(11, 0b11111111_11100000_00000000_00000000),
                testGetNetmask(12, 0b11111111_11110000_00000000_00000000),
                testGetNetmask(13, 0b11111111_11111000_00000000_00000000),
                testGetNetmask(14, 0b11111111_11111100_00000000_00000000),
                testGetNetmask(15, 0b11111111_11111110_00000000_00000000),
                testGetNetmask(16, 0b11111111_11111111_00000000_00000000),
                testGetNetmask(17, 0b11111111_11111111_10000000_00000000),
                testGetNetmask(18, 0b11111111_11111111_11000000_00000000),
                testGetNetmask(19, 0b11111111_11111111_11100000_00000000),
                testGetNetmask(20, 0b11111111_11111111_11110000_00000000),
                testGetNetmask(21, 0b11111111_11111111_11111000_00000000),
                testGetNetmask(22, 0b11111111_11111111_11111100_00000000),
                testGetNetmask(23, 0b11111111_11111111_11111110_00000000),
                testGetNetmask(24, 0b11111111_11111111_11111111_00000000),
                testGetNetmask(25, 0b11111111_11111111_11111111_10000000),
                testGetNetmask(26, 0b11111111_11111111_11111111_11000000),
                testGetNetmask(27, 0b11111111_11111111_11111111_11100000),
                testGetNetmask(28, 0b11111111_11111111_11111111_11110000),
                testGetNetmask(29, 0b11111111_11111111_11111111_11111000),
                testGetNetmask(30, 0b11111111_11111111_11111111_11111100),
                testGetNetmask(31, 0b11111111_11111111_11111111_11111110),
                testGetNetmask(32, 0b11111111_11111111_11111111_11111111),
                testGetNetmaskOfInvalidPrefixLength(-1),
                testGetNetmaskOfInvalidPrefixLength(33),
        };
    }

    private DynamicTest testGetNetmask(int prefixLength, int address) {
        return dynamicTest(Integer.toString(prefixLength), () -> assertSame(IPv4Address.valueOf(address), IPv4Address.getNetmask(prefixLength)));
    }

    private DynamicTest testGetNetmaskOfInvalidPrefixLength(int prefixLength) {
        return dynamicTest(Integer.toString(prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv4Address.getNetmask(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv4Address.BITS), exception.getMessage());
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("isValidNetmask")
    void testIsValidNetmask(IPv4Address address, boolean expected) {
        assertEquals(expected, address.isValidNetmask());
    }

    static Arguments[] testIsValidNetmask() {
        List<Arguments> arguments = new ArrayList<>();
        arguments.add(arguments(IPv4Address.LOCALHOST, false));
        arguments.add(arguments(IPv4Address.MIN_VALUE, true));
        arguments.add(arguments(IPv4Address.MIN_VALUE.next(), false));
        arguments.add(arguments(IPv4Address.MAX_VALUE, true));
        // IPv4Address.MAX_VALUE.previous() is the same as getNetmask(31)
        arguments.add(arguments(IPv4Address.MAX_VALUE.previous().previous(), false));
        for (int i = 1; i < 31; i++) {
            IPv4Address netmask = IPv4Address.getNetmask(i);
            arguments.add(arguments(netmask, true));
            arguments.add(arguments(netmask.previous(), false));
            arguments.add(arguments(netmask.next(), false));
        }
        IPv4Address netmask = IPv4Address.getNetmask(31);
        arguments.add(arguments(netmask, true));
        arguments.add(arguments(netmask.previous(), false));
        // netmask.next() is IPv4ddress.MAX_VALUE
        arguments.add(arguments(netmask.next(), true));
        return arguments.stream().toArray(Arguments[]::new);
    }

    @TestFactory
    @DisplayName("isIPv4Address")
    DynamicTest[] testIsIPv4Address() {
        return new DynamicTest[] {
                testIsIPv4Address(null, false),
                testIsIPv4Address("", false),
                testIsIPv4Address("127.0.0.1", true),
                testIsIPv4Address("0.0.0.0", true),
                testIsIPv4Address("255.255.255.255", true),
                testIsIPv4Address("12.34.56.78", true),
                testIsIPv4Address("123.456.789.0", false),
        };
    }

    private DynamicTest testIsIPv4Address(String s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv4Address.isIPv4Address(s)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("ifValidIPv4Address")
    void testIfValidIPv4Address(String s, IPv4Address expected) {
        testIfValidIPv4Address(s, expected, true);
        testIfValidIPv4Address(s, expected, false);
    }

    @SuppressWarnings("unchecked")
    private void testIfValidIPv4Address(String s, IPv4Address expected, boolean testResult) {
        Predicate<? super IPAddress<?>> predicate = mock(Predicate.class);
        when(predicate.test(any())).thenReturn(testResult);

        boolean result = IPv4Address.ifValidIPv4Address(predicate).test(s);
        if (expected != null) {
            assertEquals(testResult, result);
            verify(predicate).test(expected);
        } else {
            assertEquals(false, result);
        }
        verifyNoMoreInteractions(predicate);
    }

    static Arguments[] testIfValidIPv4Address() {
        return new Arguments[] {
                arguments(null, null),
                arguments("123.456.789.0", null),
                arguments("12.34.56.789", null),
                arguments("127.0.0.1", IPv4Address.LOCALHOST),
        };
    }
}
