/*
 * IPv6AddressTest.java
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class IPv6AddressTest {

    @Test
    public void testBits() {
        assertEquals(128, IPv6Address.LOCALHOST.bits());
    }

    @TestFactory
    public DynamicTest[] testToByteArray() {
        return new DynamicTest[] {
                testToByteArray(IPv6Address.LOCALHOST, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
                testToByteArray(IPv6Address.MIN_VALUE, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }),
                testToByteArray(IPv6Address.MAX_VALUE, new byte[] {
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255
                }),
                testToByteArray(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), new byte[] {
                        0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                        0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12
                }),
        };
    }

    private DynamicTest testToByteArray(IPv6Address address, byte[] expected) {
        return dynamicTest(address.toString(), () -> assertArrayEquals(expected, address.toByteArray()));
    }

    @TestFactory
    public DynamicTest[] testToInetAddress() {
        return new DynamicTest[] {
                testToInetAddress(IPv6Address.LOCALHOST, "::1"),
                testToInetAddress(IPv6Address.MIN_VALUE, "::"),
                testToInetAddress(IPv6Address.MAX_VALUE, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                testToInetAddress(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF), "1234:5678:90ab::cdef"),
        };
    }

    private DynamicTest testToInetAddress(IPv6Address address, String expected) {
        return dynamicTest(address.toString(), () -> {
            assertEquals(InetAddress.getByName(expected), address.toInetAddress());
            // test caching
            assertSame(address.toInetAddress(), address.toInetAddress());
        });
    }

    @TestFactory
    public DynamicTest[] testToIPv4() {
        return new DynamicTest[] {
                testToIPv4NotMapped(IPv6Address.LOCALHOST),
                testToIPv4NotMapped(IPv6Address.MIN_VALUE),
                testToIPv4NotMapped(IPv6Address.MAX_VALUE),
                testToIPv4NotMapped(IPv6Address.valueOf(0L, 0x0000_FFFE_FFFF_FFFFL)),
                testToIPv4(IPv6Address.valueOf(0L, 0x0000_FFFF_0000_0000L), IPv4Address.MIN_VALUE),
                testToIPv4(IPv6Address.valueOf(0L, 0x0000_FFFF_FFFF_FFFFL), IPv4Address.MAX_VALUE),
                testToIPv4NotMapped(IPv6Address.valueOf(0L, 0x0001_0000_0000_0000L)),
                testToIPv4NotMapped(IPv6Address.valueOf(1L, 0x0000_FFFE_FFFF_FFFFL)),
                testToIPv4NotMapped(IPv6Address.valueOf(1L, 0x0000_FFFF_0000_0000L)),
                testToIPv4NotMapped(IPv6Address.valueOf(1L, 0x0000_FFFF_FFFF_FFFFL)),
                testToIPv4NotMapped(IPv6Address.valueOf(1L, 0x0001_0000_0000_0000L)),
        };
    }

    private DynamicTest testToIPv4(IPv6Address address, IPv4Address expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.toIPv4()));
    }

    private DynamicTest testToIPv4NotMapped(IPv6Address address) {
        return dynamicTest(address.toString(), () -> {
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> address.toIPv4());
            assertEquals(Messages.IPv6Address.notIPv4Mapped.get(address), exception.getMessage());
        });
    }

    // isIPv4Mapped is tested with toIPv4

    @TestFactory
    public DynamicTest[] testEquals() {
        IPv6Address address = IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12);
        return new DynamicTest[] {
                testEquals(address, null, false),
                testEquals(address, "foo", false),
                testEquals(address, IPv4Address.valueOf(12, 34, 56, 78), false),
                testEquals(address, address, true),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), true),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0, 0xABCD, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0, 0x7890, 0xABCD, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0x5678, 0, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0x1234, 0, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testEquals(address, IPv6Address.valueOf(0, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
        };
    }

    private DynamicTest testEquals(IPv6Address address, Object object, boolean expectEquals) {
        BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        return dynamicTest(String.valueOf(object), () -> equalsCheck.accept(address, object));
    }

    @TestFactory
    public DynamicTest[] testHashCode() {
        IPv6Address address = IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12);
        return new DynamicTest[] {
                testHashCode(address, address, true),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), true),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0, 0xABCD, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0, 0x7890, 0xABCD, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0x5678, 0, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0x1234, 0, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
                testHashCode(address, IPv6Address.valueOf(0, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12), false),
        };
    }

    private DynamicTest testHashCode(IPv6Address address, IPv6Address other, boolean expectEquals) {
        BiConsumer<Integer, Integer> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        return dynamicTest(other.toString(), () -> equalsCheck.accept(address.hashCode(), other.hashCode()));
    }

    @TestFactory
    public DynamicTest[] testToString() {
        return new DynamicTest[] {
                testToString(IPv6Address.LOCALHOST, "::1"),
                testToString(IPv6Address.MIN_VALUE, "::"),
                testToString(IPv6Address.MAX_VALUE, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                testToString(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12),
                        "1234:5678:90ab:cdef:3456:7890:abcd:ef12"),
                testToString(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF), "1234:5678:90ab::cdef"),
                testToString(IPv6Address.valueOf(1, 0, 0, 0, 0, 0, 0, 0), "1::"),
                testToString(IPv6Address.valueOf(1, 0, 0, 0, 0, 0, 0, 1), "1::1"),
                testToString(IPv6Address.valueOf(1, 0, 0, 1, 0, 0, 0, 1), "1:0:0:1::1"),
                testToString(IPv6Address.valueOf(1, 0, 0, 0, 1, 0, 0, 1), "1::1:0:0:1"),
        };
    }

    private DynamicTest testToString(IPv6Address address, String expected) {
        return dynamicTest(address.toString(), () -> {
            assertEquals(expected, address.toString());
            // test caching
            assertSame(address.toString(), address.toString());
        });
    }

    @TestFactory
    public DynamicTest[] testCompareTo() {
        IPv6Address address = IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12);
        return new DynamicTest[] {
                testCompareToEqual(IPv6Address.LOCALHOST, IPv6Address.LOCALHOST),
                testCompareToLarger(IPv6Address.LOCALHOST, IPv6Address.MIN_VALUE),
                testCompareToSmaller(IPv6Address.LOCALHOST, IPv6Address.MAX_VALUE),

                testCompareToEqual(address, address),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF13)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF11)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCE, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCC, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7891, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7889, 0xABCD, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3457, 0x7890, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3455, 0x7890, 0xABCD, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDF0, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEE, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AC, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5678, 0x90AA, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1234, 0x5679, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1234, 0x5677, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToSmaller(address, IPv6Address.valueOf(0x1235, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testCompareToLarger(address, IPv6Address.valueOf(0x1233, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
        };
    }

    private DynamicTest testCompareToEqual(IPv6Address address, IPv6Address other) {
        return dynamicTest(other.toString(), () -> assertTrue(address.compareTo(other) == 0));
    }

    private DynamicTest testCompareToSmaller(IPv6Address address, IPv6Address other) {
        return dynamicTest(other.toString(), () -> assertTrue(address.compareTo(other) < 0));
    }

    private DynamicTest testCompareToLarger(IPv6Address address, IPv6Address other) {
        return dynamicTest(other.toString(), () -> assertTrue(address.compareTo(other) > 0));
    }

    @TestFactory
    public DynamicTest[] testIsMulticastAddress() {
        return new DynamicTest[] {
                testIsMulticastAddress(IPv6Address.LOCALHOST, false),
                testIsMulticastAddress(IPv6Address.MIN_VALUE, false),
                testIsMulticastAddress(IPv6Address.MAX_VALUE, true),
                testIsMulticastAddress(IPv6Address.valueOf(0xFEFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), false),
                testIsMulticastAddress(IPv6Address.valueOf(0xFF00, 0, 0, 0, 0, 0, 0, 0), true),
                testIsMulticastAddress(IPv6Address.valueOf(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), true),
        };
    }

    private DynamicTest testIsMulticastAddress(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isMulticastAddress()));
    }

    @TestFactory
    public DynamicTest[] testIsWildcardAddress() {
        return new DynamicTest[] {
                testIsWildcardAddress(IPv6Address.LOCALHOST, false),
                testIsWildcardAddress(IPv6Address.MIN_VALUE, true),
                testIsWildcardAddress(IPv6Address.MAX_VALUE, false),
                testIsWildcardAddress(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 1), false),
        };
    }

    private DynamicTest testIsWildcardAddress(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isWildcardAddress()));
    }

    @TestFactory
    public DynamicTest[] testIsLoopbackAddress() {
        return new DynamicTest[] {
                testIsLoopbackAddress(IPv6Address.LOCALHOST, true),
                testIsLoopbackAddress(IPv6Address.MIN_VALUE, false),
                testIsLoopbackAddress(IPv6Address.MAX_VALUE, false),
                testIsLoopbackAddress(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 2), false),
        };
    }

    private DynamicTest testIsLoopbackAddress(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isLoopbackAddress()));
    }

    @TestFactory
    public DynamicTest[] testIsLinkLocalAddress() {
        return new DynamicTest[] {
                testIsLinkLocalAddress(IPv6Address.LOCALHOST, false),
                testIsLinkLocalAddress(IPv6Address.MIN_VALUE, false),
                testIsLinkLocalAddress(IPv6Address.MAX_VALUE, false),
                testIsLinkLocalAddress(IPv6Address.valueOf(0xFE7F, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), false),
                testIsLinkLocalAddress(IPv6Address.valueOf(0xFE80, 0, 0, 0, 0, 0, 0, 0), true),
                testIsLinkLocalAddress(IPv6Address.valueOf(0xFEBF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF , 0xFFFF, 0xFFFF), true),
                testIsLinkLocalAddress(IPv6Address.valueOf(0xFEC0, 0, 0, 0, 0, 0, 0, 0), false),
        };
    }

    private DynamicTest testIsLinkLocalAddress(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isLinkLocalAddress()));
    }

    @TestFactory
    public DynamicTest[] testIsSiteLocalAddress() {
        return new DynamicTest[] {
                testIsSiteLocalAddress(IPv6Address.LOCALHOST, false),
                testIsSiteLocalAddress(IPv6Address.MIN_VALUE, false),
                testIsSiteLocalAddress(IPv6Address.MAX_VALUE, false),
                testIsSiteLocalAddress(IPv6Address.valueOf(0xFEBF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), false),
                testIsSiteLocalAddress(IPv6Address.valueOf(0xFEC0, 0, 0, 0, 0, 0, 0, 0), true),
                testIsSiteLocalAddress(IPv6Address.valueOf(0xFEFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), true),
                testIsSiteLocalAddress(IPv6Address.valueOf(0xFF00, 0, 0, 0, 0, 0, 0, 0), false),
        };
    }

    private DynamicTest testIsSiteLocalAddress(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isSiteLocalAddress()));
    }

    @TestFactory
    public DynamicTest[] testHasNext() {
        return new DynamicTest[] {
                testHasNext(IPv6Address.LOCALHOST, true),
                testHasNext(IPv6Address.MIN_VALUE, true),
                testHasNext(IPv6Address.MAX_VALUE, false),
                testHasNext(IPv6Address.valueOf(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE), true),
        };
    }

    private DynamicTest testHasNext(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.hasNext()));
    }

    @TestFactory
    public DynamicTest[] testNext() {
        return new DynamicTest[] {
                testNext(IPv6Address.LOCALHOST, IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 2)),
                testNext(IPv6Address.MIN_VALUE, IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 1)),
                testNext(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12),
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF13)),
                testNext(IPv6Address.valueOf(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE), IPv6Address.MAX_VALUE),
                testNext(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDF0, 0, 0, 0, 0)),
                dynamicTest(IPv6Address.MAX_VALUE.toString(), () -> assertThrows(NoSuchElementException.class, IPv6Address.MAX_VALUE::next)),
        };
    }

    private DynamicTest testNext(IPv6Address address, IPv6Address expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.next()));
    }

    @TestFactory
    public DynamicTest[] testHasPrevious() {
        return new DynamicTest[] {
                testHasPrevious(IPv6Address.LOCALHOST, true),
                testHasPrevious(IPv6Address.MIN_VALUE, false),
                testHasPrevious(IPv6Address.MAX_VALUE, true),
                testHasPrevious(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 1), true),
        };
    }

    private DynamicTest testHasPrevious(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.hasPrevious()));
    }

    @TestFactory
    public DynamicTest[] testPrevious() {
        return new DynamicTest[] {
                testPrevious(IPv6Address.LOCALHOST, IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0)),
                testPrevious(IPv6Address.MAX_VALUE, IPv6Address.valueOf(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE)),
                testPrevious(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12),
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF11)),
                testPrevious(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 1), IPv6Address.MIN_VALUE),
                testPrevious(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDF0, 0, 0, 0, 0),
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)),
                dynamicTest(IPv6Address.MIN_VALUE.toString(), () -> assertThrows(NoSuchElementException.class, IPv6Address.MIN_VALUE::previous)),
        };
    }

    private DynamicTest testPrevious(IPv6Address address, IPv6Address expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.previous()));
    }

    @TestFactory
    public DynamicTest[] testMid() {
        return new DynamicTest[] {
                testMid(IPv6Address.LOCALHOST, IPv6Address.LOCALHOST, IPv6Address.LOCALHOST),
                testMid(IPv6Address.LOCALHOST, IPv6Address.LOCALHOST.next(), IPv6Address.LOCALHOST),
                testMid(IPv6Address.LOCALHOST.next(), IPv6Address.LOCALHOST, IPv6Address.LOCALHOST),
                testMid(IPv6Address.LOCALHOST.previous(), IPv6Address.LOCALHOST.next(), IPv6Address.LOCALHOST),
                testMid(IPv6Address.MIN_VALUE, IPv6Address.MIN_VALUE, IPv6Address.MIN_VALUE),
                testMid(IPv6Address.MIN_VALUE, IPv6Address.MIN_VALUE.next(), IPv6Address.MIN_VALUE),
                testMid(IPv6Address.MAX_VALUE, IPv6Address.MAX_VALUE, IPv6Address.MAX_VALUE),
                testMid(IPv6Address.MAX_VALUE.previous(), IPv6Address.MAX_VALUE, IPv6Address.MAX_VALUE.previous()),
                testMid(IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE, IPv6Address.valueOf(Long.MAX_VALUE, IPv6Address.MAX_LOW_ADDRESS)),
                testMid(IPv6Address.valueOf(Long.MAX_VALUE, 0), IPv6Address.valueOf(Long.MAX_VALUE, IPv6Address.MAX_LOW_ADDRESS),
                        IPv6Address.valueOf(Long.MAX_VALUE, Long.MAX_VALUE)),
                testMid(IPv6Address.valueOf(0, Integer.MAX_VALUE), IPv6Address.valueOf(IPv6Address.MAX_HIGH_ADDRESS, Integer.MAX_VALUE + 1L),
                        IPv6Address.valueOf(Long.MAX_VALUE, 0x8000_0000_7FFF_FFFFL)),
                testMid(IPv6Address.valueOf(IPv6Address.MAX_HIGH_ADDRESS, Integer.MAX_VALUE + 1L), IPv6Address.valueOf(0, Integer.MAX_VALUE),
                        IPv6Address.valueOf(Long.MAX_VALUE, 0x8000_0000_7FFF_FFFFL)),
        };
    }

    private DynamicTest testMid(IPv6Address low, IPv6Address high, IPv6Address expected) {
        return dynamicTest(String.format("%s.mid(%s)", low, high), () -> assertEquals(expected, low.mid(high)));
    }

    @TestFactory
    public DynamicTest[] testTo() {
        // Don't test the range itself, only its to and from values. The range has its own tests.
        return new DynamicTest[] {
                dynamicTest("MIN_VALUE to MAX_VALUE", () -> {
                    IPv6Range range = IPv6Address.MIN_VALUE.to(IPv6Address.MAX_VALUE);
                    assertEquals(IPv6Address.MIN_VALUE, range.from());
                    assertEquals(IPv6Address.MAX_VALUE, range.to());
                    assertEquals(IPRangeImpl.IPv6.class, range.getClass());
                }),
                dynamicTest("MIN_VALUE to MIN_VALUE", () -> {
                    IPv6Range range = IPv6Address.MIN_VALUE.to(IPv6Address.MIN_VALUE);
                    assertEquals(IPv6Address.MIN_VALUE, range.from());
                    assertEquals(IPv6Address.MIN_VALUE, range.to());
                    assertEquals(SingletonIPRange.IPv6.class, range.getClass());
                }),
                dynamicTest("MAX_VALUE to MIN_VALUE", () -> {
                    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                            () -> IPv6Address.MAX_VALUE.to(IPv6Address.MIN_VALUE));
                    assertEquals(Messages.IPRange.toSmallerThanFrom.get(IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE), exception.getMessage());
                }),
        };
    }

    @Test
    public void testAsRange() {
        // Don't test the range itself, only its to and from values. The range has its own tests.
        IPv6Range range = IPv6Address.MIN_VALUE.asRange();
        assertEquals(IPv6Address.MIN_VALUE, range.from());
        assertEquals(IPv6Address.MIN_VALUE, range.to());
        assertEquals(SingletonIPRange.IPv6.class, range.getClass());
    }

    @TestFactory
    public DynamicTest[] testInSubnet() {
        IPv6Address address = IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_00EFL);
        return new DynamicTest[] {
                testInSubnet(IPv6Address.LOCALHOST, 0, IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE),
                testInSubnet(IPv6Address.LOCALHOST, 128, IPv6Address.LOCALHOST, IPv6Address.LOCALHOST),
                testInSubnet(address, 0, IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE),
                testInSubnet(address, 16, IPv6Address.valueOf(0x0012_0000_0000_0000L, 0x0000_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testInSubnet(address, 32, IPv6Address.valueOf(0x0012_0034_0000_0000L, 0x0000_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testInSubnet(address, 48, IPv6Address.valueOf(0x0012_0034_0056_0000L, 0x0000_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testInSubnet(address, 64, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0000_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0xFFFF_FFFF_FFFF_FFFFL)),
                testInSubnet(address, 80, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_0000_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_FFFF_FFFF_FFFFL)),
                testInSubnet(address, 96, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_0000_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_FFFF_FFFFL)),
                testInSubnet(address, 112, IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_0000L),
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_FFFFL)),
                testInSubnet(address, 128, address, address),
                testInSubnetInvalidPrefixLength(-1),
                testInSubnetInvalidPrefixLength(129),
        };
    }

    private DynamicTest testInSubnet(IPv6Address address, int prefixLength, IPv6Address expectedFrom, IPv6Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv6Subnet subnet = address.inSubnet(prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertEquals(expectedFrom, subnet.routingPrefix());
            assertEquals(expectedFrom, subnet.from());
            assertEquals(expectedTo, subnet.to());
        });
    }

    private DynamicTest testInSubnetInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Address.LOCALHOST.inSubnet(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testStartingSubnet() {
        IPv6Address address = IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_00EFL);
        return new DynamicTest[] {
                testStartingSubnetInvalidRoutingPrefix(IPv6Address.LOCALHOST, 0),
                testStartingSubnet(IPv6Address.LOCALHOST, 128, IPv6Address.LOCALHOST),
                testStartingSubnet(IPv6Address.MIN_VALUE, 0, IPv6Address.MAX_VALUE),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0000_0000_0000L, 0x0000_0000_0000_0000L), 16,
                        IPv6Address.valueOf(0x0012_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0000_0000L, 0x0000_0000_0000_0000L), 32,
                        IPv6Address.valueOf(0x0012_0034_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0056_0000L, 0x0000_0000_0000_0000L), 48,
                        IPv6Address.valueOf(0x0012_0034_0056_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0000_0000_0000_0000L), 64,
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0xFFFF_FFFF_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_0000_0000_0000L), 80,
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_FFFF_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_0000_0000L), 96,
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_FFFF_FFFFL)),
                testStartingSubnet(IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_0000L), 112,
                        IPv6Address.valueOf(0x0012_0034_0056_0078L, 0x0090_00AB_00CD_FFFFL)),
                testStartingSubnet(address, 128, address),
                testStartingSubnetInvalidRoutingPrefix(address, 16),
                testStartingSubnetInvalidRoutingPrefix(address, 32),
                testStartingSubnetInvalidRoutingPrefix(address, 48),
                testStartingSubnetInvalidRoutingPrefix(address, 64),
                testStartingSubnetInvalidRoutingPrefix(address, 80),
                testStartingSubnetInvalidRoutingPrefix(address, 96),
                testStartingSubnetInvalidRoutingPrefix(address, 112),
                testStartingSubnetInvalidPrefixLength(-1),
                testStartingSubnetInvalidPrefixLength(129),
        };
    }

    private DynamicTest testStartingSubnet(IPv6Address address, int prefixLength, IPv6Address expectedTo) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IPv6Subnet subnet = address.startingSubnet(prefixLength);
            assertEquals(prefixLength, subnet.prefixLength());
            assertSame(address, subnet.routingPrefix());
            assertSame(address, subnet.from());
            assertEquals(expectedTo, subnet.to());
            if (expectedTo.equals(address)) {
                assertSame(address, subnet.to());
            }
        });
    }

    private DynamicTest testStartingSubnetInvalidRoutingPrefix(IPv6Address address, int prefixLength) {
        return dynamicTest(String.format("%s/%d", address, prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> address.startingSubnet(prefixLength));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testStartingSubnetInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> IPv6Address.MIN_VALUE.startingSubnet(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testValueOfHextets() {
        return new DynamicTest[] {
                testValueOfHextets(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12,
                        IPv6Address.valueOf(0x1234567890ABCDEFL, 0x34567890ABCDEF12L)),
                testValueOfHextets(0, 0, 0, 0, 0, 0, 0, 0, IPv6Address.MIN_VALUE),
                testValueOfHextets(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, IPv6Address.MAX_VALUE),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, 0, 0, -1, -1),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, 0, 0, 0x10000, 0x10000),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, 0, -1, 0, -1),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, 0, 0x10000, 0, 0x10000),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, -1, 0, 0, -1),
                testValueOfInvalidHextets(0, 0, 0, 0, 0, 0x10000, 0, 0, 0x10000),
                testValueOfInvalidHextets(0, 0, 0, 0, -1, 0, 0, 0, -1),
                testValueOfInvalidHextets(0, 0, 0, 0, 0x10000, 0, 0, 0, 0x10000),
                testValueOfInvalidHextets(0, 0, 0, -1, 0, 0, 0, 0, -1),
                testValueOfInvalidHextets(0, 0, 0, 0x10000, 0, 0, 0, 0, 0x10000),
                testValueOfInvalidHextets(0, 0, -1, 0, 0, 0, 0, 0, -1),
                testValueOfInvalidHextets(0, 0, 0x10000, 0, 0, 0, 0, 0, 0x10000),
                testValueOfInvalidHextets(0, -1, 0, 0, 0, 0, 0, 0, -1),
                testValueOfInvalidHextets(0, 0x10000, 0, 0, 0, 0, 0, 0, 0x10000),
                testValueOfInvalidHextets(-1, 0, 0, 0, 0, 0, 0, 0, -1),
                testValueOfInvalidHextets(0x10000, 0, 0, 0, 0, 0, 0, 0, 0x10000),
        };
    }

    private DynamicTest testValueOfHextets(int hextet1, int hextet2, int hextet3, int hextet4, int hextet5, int hextet6, int hextet7, int hextet8,
            IPv6Address expected) {

        return dynamicTest(String.format("%x:%x:%x:%x:%x:%x:%x:%x", hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8),
                () -> assertEquals(expected, IPv6Address.valueOf(hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8)));
    }

    private DynamicTest testValueOfInvalidHextets(int hextet1, int hextet2, int hextet3, int hextet4,
            int hextet5, int hextet6, int hextet7, int hextet8, int firstInvalidHextet) {

        return dynamicTest(String.format("%x:%x:%x:%x:%x:%x:%x:%x", hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> IPv6Address.valueOf(hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8));
            assertEquals(Messages.IPv6Address.invalidHextet.get(firstInvalidHextet), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testValueOfByteArray() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPv6Address.valueOf((byte[]) null))),
                testValueOfByteArray(new byte[] {
                        0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                        0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12
                }, IPv6Address.valueOf(0x1234567890ABCDEFL, 0x34567890ABCDEF12L)),
                testValueOfByteArray(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, IPv6Address.MIN_VALUE),
                testValueOfByteArray(new byte[] {
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255
                }, IPv6Address.MAX_VALUE),
                testValueOfByteArrayOfInvalidSize(new byte[0]),
                testValueOfByteArrayOfInvalidSize(new byte[4]),
                testValueOfByteArrayOfInvalidSize(new byte[15]),
                testValueOfByteArrayOfInvalidSize(new byte[17]),
        };
    }

    private DynamicTest testValueOfByteArray(byte[] address, IPv6Address expected) {
        return dynamicTest(Arrays.toString(address), () -> assertEquals(expected, IPv6Address.valueOf(address)));
    }

    private DynamicTest testValueOfByteArrayOfInvalidSize(byte[] address) {
        return dynamicTest(Arrays.toString(address), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Address.valueOf(address));
            assertEquals(Messages.IPAddress.invalidArraySize.get(address.length), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testValueOfCharSequence() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPv6Address.valueOf((CharSequence) null))),
                testValueOfCharSequence("::1", IPv6Address.LOCALHOST),
                testValueOfCharSequence("::", IPv6Address.MIN_VALUE),
                testValueOfCharSequence("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),
                testValueOfCharSequence("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testValueOfCharSequence("1234:5678:90ab::cdef", IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF)),
                testValueOfCharSequence("::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1)),
                // Just two invalid cases. The parsing has its own tests.
                testValueOfInvalidCharSequence("12345:6789:0abc:def3:4567:890a:bcde:f123"),
                testValueOfInvalidCharSequence("1234:5678:90ab:cdef:3456:7890:abcd:ef123"),
        };
    }

    private DynamicTest testValueOfCharSequence(String address, IPv6Address expected) {
        return dynamicTest(address, () -> assertEquals(expected, IPv6Address.valueOf(address)));
    }

    private DynamicTest testValueOfInvalidCharSequence(String address) {
        return dynamicTest(address, () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Address.valueOf(address));
            assertEquals(Messages.IPAddress.invalidIPAddress.get(address), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testTryValueOf() {
        return new DynamicTest[] {
                testTryValueOf(null, Optional.empty()),
                testTryValueOf("", Optional.empty()),
                testTryValueOf("::1", Optional.of(IPv6Address.LOCALHOST)),
                testTryValueOf("::", Optional.of(IPv6Address.MIN_VALUE)),
                testTryValueOf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Optional.of(IPv6Address.MAX_VALUE)),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        Optional.of(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12))),
                testTryValueOf("1234:5678:90ab::cdef", Optional.of(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF))),
                testTryValueOf("::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1))),
                // Just four invalid cases. The parsing has its own tests.
                testTryValueOf("12345:6789:0abc:def3:4567:890a:bcde:f123", Optional.empty()),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef123", Optional.empty()),
                testTryValueOf("123.456.789.0", Optional.empty()),
                testTryValueOf("12.34.56.789", Optional.empty()),
                testTryValueOf("127.0.0.1", Optional.empty()),
                testTryValueOf("0.0.0.0", Optional.empty()),
                testTryValueOf("255.255.255.255", Optional.empty()),
                testTryValueOf("12.34.56.78", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOf(String address, Optional<IPv6Address> expected) {
        String displayName = String.valueOf(address);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv6Address.tryValueOfIPv6(address)));
    }

    @TestFactory
    public DynamicTest[] testValueOfInetAddress() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPAddress.valueOf((InetAddress) null))),
                testValueOfInetAddress("::1", IPv6Address.LOCALHOST),
                testValueOfInetAddress("::", IPv6Address.MIN_VALUE),
                testValueOfInetAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),
                testValueOfInetAddress("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testValueOfInetAddress("1234:5678:90ab::cdef", IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF)),
                testValueOfInetAddress("::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1)),
        };
    }

    private DynamicTest testValueOfInetAddress(String address, IPv6Address expected) {
        return dynamicTest(address, () -> assertEquals(expected, IPv6Address.valueOf((Inet6Address) InetAddress.getByName(address))));
    }

    @TestFactory
    public DynamicTest[] testGetNetmask() {
        return new DynamicTest[] {
                testGetNetmask(0, 0L, 0L),
                testGetNetmask(1, 0x8000_0000_0000_0000L, 0L),
                testGetNetmask(2, 0xC000_0000_0000_0000L, 0L),
                testGetNetmask(3, 0xE000_0000_0000__0000L, 0L),
                testGetNetmask(4, 0xF000_0000_0000_0000L, 0L),
                testGetNetmask(5, 0xF800_0000_0000_0000L, 0L),
                testGetNetmask(6, 0xFC00_0000_0000_0000L, 0L),
                testGetNetmask(7, 0xFE00_0000_0000_0000L, 0L),
                testGetNetmask(8, 0xFF00_0000_0000_0000L, 0L),
                testGetNetmask(9, 0xFF80_0000_0000_0000L, 0L),
                testGetNetmask(10, 0xFFC0_0000_0000_0000L, 0L),
                testGetNetmask(11, 0xFFE0_0000_0000_0000L, 0L),
                testGetNetmask(12, 0xFFF0_0000_0000_0000L, 0L),
                testGetNetmask(13, 0xFFF8_0000_0000_0000L, 0L),
                testGetNetmask(14, 0xFFFC_0000_0000_0000L, 0L),
                testGetNetmask(15, 0xFFFE_0000_0000_0000L, 0L),
                testGetNetmask(16, 0xFFFF_0000_0000_0000L, 0L),
                testGetNetmask(17, 0xFFFF_8000_0000_0000L, 0L),
                testGetNetmask(18, 0xFFFF_C000_0000_0000L, 0L),
                testGetNetmask(19, 0xFFFF_E000_0000_0000L, 0L),
                testGetNetmask(20, 0xFFFF_F000_0000_0000L, 0L),
                testGetNetmask(21, 0xFFFF_F800_0000_0000L, 0L),
                testGetNetmask(22, 0xFFFF_FC00_0000_0000L, 0L),
                testGetNetmask(23, 0xFFFF_FE00_0000_0000L, 0L),
                testGetNetmask(24, 0xFFFF_FF00_0000_0000L, 0L),
                testGetNetmask(25, 0xFFFF_FF80_0000_0000L, 0L),
                testGetNetmask(26, 0xFFFF_FFC0_0000_0000L, 0L),
                testGetNetmask(27, 0xFFFF_FFE0_0000_0000L, 0L),
                testGetNetmask(28, 0xFFFF_FFF0_0000_0000L, 0L),
                testGetNetmask(29, 0xFFFF_FFF8_0000_0000L, 0L),
                testGetNetmask(30, 0xFFFF_FFFC_0000_0000L, 0L),
                testGetNetmask(31, 0xFFFF_FFFE_0000_0000L, 0L),
                testGetNetmask(32, 0xFFFF_FFFF_0000_0000L, 0L),
                testGetNetmask(33, 0xFFFF_FFFF_8000_0000L, 0L),
                testGetNetmask(34, 0xFFFF_FFFF_C000_0000L, 0L),
                testGetNetmask(35, 0xFFFF_FFFF_E000_0000L, 0L),
                testGetNetmask(36, 0xFFFF_FFFF_F000_0000L, 0L),
                testGetNetmask(37, 0xFFFF_FFFF_F800_0000L, 0L),
                testGetNetmask(38, 0xFFFF_FFFF_FC00_0000L, 0L),
                testGetNetmask(39, 0xFFFF_FFFF_FE00_0000L, 0L),
                testGetNetmask(40, 0xFFFF_FFFF_FF00_0000L, 0L),
                testGetNetmask(41, 0xFFFF_FFFF_FF80_0000L, 0L),
                testGetNetmask(42, 0xFFFF_FFFF_FFC0_0000L, 0L),
                testGetNetmask(43, 0xFFFF_FFFF_FFE0_0000L, 0L),
                testGetNetmask(44, 0xFFFF_FFFF_FFF0_0000L, 0L),
                testGetNetmask(45, 0xFFFF_FFFF_FFF8_0000L, 0L),
                testGetNetmask(46, 0xFFFF_FFFF_FFFC_0000L, 0L),
                testGetNetmask(47, 0xFFFF_FFFF_FFFE_0000L, 0L),
                testGetNetmask(48, 0xFFFF_FFFF_FFFF_0000L, 0L),
                testGetNetmask(49, 0xFFFF_FFFF_FFFF_8000L, 0L),
                testGetNetmask(50, 0xFFFF_FFFF_FFFF_C000L, 0L),
                testGetNetmask(51, 0xFFFF_FFFF_FFFF_E000L, 0L),
                testGetNetmask(52, 0xFFFF_FFFF_FFFF_F000L, 0L),
                testGetNetmask(53, 0xFFFF_FFFF_FFFF_F800L, 0L),
                testGetNetmask(54, 0xFFFF_FFFF_FFFF_FC00L, 0L),
                testGetNetmask(55, 0xFFFF_FFFF_FFFF_FE00L, 0L),
                testGetNetmask(56, 0xFFFF_FFFF_FFFF_FF00L, 0L),
                testGetNetmask(57, 0xFFFF_FFFF_FFFF_FF80L, 0L),
                testGetNetmask(58, 0xFFFF_FFFF_FFFF_FFC0L, 0L),
                testGetNetmask(59, 0xFFFF_FFFF_FFFF_FFE0L, 0L),
                testGetNetmask(60, 0xFFFF_FFFF_FFFF_FFF0L, 0L),
                testGetNetmask(61, 0xFFFF_FFFF_FFFF_FFF8L, 0L),
                testGetNetmask(62, 0xFFFF_FFFF_FFFF_FFFCL, 0L),
                testGetNetmask(63, 0xFFFF_FFFF_FFFF_FFFEL, 0L),
                testGetNetmask(64, 0xFFFF_FFFF_FFFF_FFFFL, 0L),
                testGetNetmask(65, 0xFFFF_FFFF_FFFF_FFFFL, 0x8000_0000_0000_0000L),
                testGetNetmask(66, 0xFFFF_FFFF_FFFF_FFFFL, 0xC000_0000_0000_0000L),
                testGetNetmask(67, 0xFFFF_FFFF_FFFF_FFFFL, 0xE000_0000_0000_0000L),
                testGetNetmask(68, 0xFFFF_FFFF_FFFF_FFFFL, 0xF000_0000_0000_0000L),
                testGetNetmask(69, 0xFFFF_FFFF_FFFF_FFFFL, 0xF800_0000_0000_0000L),
                testGetNetmask(70, 0xFFFF_FFFF_FFFF_FFFFL, 0xFC00_0000_0000_0000L),
                testGetNetmask(71, 0xFFFF_FFFF_FFFF_FFFFL, 0xFE00_0000_0000_0000L),
                testGetNetmask(72, 0xFFFF_FFFF_FFFF_FFFFL, 0xFF00_0000_0000_0000L),
                testGetNetmask(73, 0xFFFF_FFFF_FFFF_FFFFL, 0xFF80_0000_0000_0000L),
                testGetNetmask(74, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFC0_0000_0000_0000L),
                testGetNetmask(75, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFE0_0000_0000_0000L),
                testGetNetmask(76, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFF0_0000_0000_0000L),
                testGetNetmask(77, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFF8_0000_0000_0000L),
                testGetNetmask(78, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFC_0000_0000_0000L),
                testGetNetmask(79, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFE_0000_0000_0000L),
                testGetNetmask(80, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_0000_0000_0000L),
                testGetNetmask(81, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_8000_0000_0000L),
                testGetNetmask(82, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_C000_0000_0000L),
                testGetNetmask(83, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_E000_0000_0000L),
                testGetNetmask(84, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_F000_0000_0000L),
                testGetNetmask(85, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_F800_0000_0000L),
                testGetNetmask(86, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FC00_0000_0000L),
                testGetNetmask(87, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FE00_0000_0000L),
                testGetNetmask(88, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FF00_0000_0000L),
                testGetNetmask(89, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FF80_0000_0000L),
                testGetNetmask(90, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFC0_0000_0000L),
                testGetNetmask(91, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFE0_0000_0000L),
                testGetNetmask(92, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFF0_0000_0000L),
                testGetNetmask(93, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFF8_0000_0000L),
                testGetNetmask(94, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFC_0000_0000L),
                testGetNetmask(95, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFE_0000_0000L),
                testGetNetmask(96, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_0000_0000L),
                testGetNetmask(97, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_8000_0000L),
                testGetNetmask(98, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_C000_0000L),
                testGetNetmask(99, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_E000_0000L),
                testGetNetmask(100, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_F000_0000L),
                testGetNetmask(101, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_F800_0000L),
                testGetNetmask(102, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FC00_0000L),
                testGetNetmask(103, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FE00_0000L),
                testGetNetmask(104, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FF00_0000L),
                testGetNetmask(105, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FF80_0000L),
                testGetNetmask(106, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFC0_0000L),
                testGetNetmask(107, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFE0_0000L),
                testGetNetmask(108, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFF0_0000L),
                testGetNetmask(109, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFF8_0000L),
                testGetNetmask(110, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFC_0000L),
                testGetNetmask(111, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFE_0000L),
                testGetNetmask(112, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_0000L),
                testGetNetmask(113, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_8000L),
                testGetNetmask(114, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_C000L),
                testGetNetmask(115, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_E000L),
                testGetNetmask(116, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_F000L),
                testGetNetmask(117, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_F800L),
                testGetNetmask(118, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FC00L),
                testGetNetmask(119, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FE00L),
                testGetNetmask(120, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FF00L),
                testGetNetmask(121, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FF80L),
                testGetNetmask(122, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFC0L),
                testGetNetmask(123, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFE0L),
                testGetNetmask(124, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFF0L),
                testGetNetmask(125, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFF8L),
                testGetNetmask(126, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFCL),
                testGetNetmask(127, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFEL),
                testGetNetmask(128, 0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL),
                testGetNetmaskOfInvalidPrefixLength(-1),
                testGetNetmaskOfInvalidPrefixLength(129),
        };
    }

    private DynamicTest testGetNetmask(int prefixLength, long highAddress, long lowAddress) {
        return dynamicTest(Integer.toString(prefixLength),
                () -> assertSame(IPv6Address.valueOf(highAddress, lowAddress), IPv6Address.getNetmask(prefixLength)));
    }

    private DynamicTest testGetNetmaskOfInvalidPrefixLength(int prefixLength) {
        return dynamicTest(Integer.toString(prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Address.getNetmask(prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testIsValidNetmask() {
        List<DynamicTest> tests = new ArrayList<>();
        tests.add(testIsValidNetmask(IPv6Address.LOCALHOST, false));
        tests.add(testIsValidNetmask(IPv6Address.MIN_VALUE, true));
        tests.add(testIsValidNetmask(IPv6Address.MIN_VALUE.next(), false));
        tests.add(testIsValidNetmask(IPv6Address.MAX_VALUE, true));
        // IPv6Address.MAX_VALUE.previous() is the same as getNetmask(127)
        tests.add(testIsValidNetmask(IPv6Address.MAX_VALUE.previous().previous(), false));
        for (int i = 1; i < 127; i++) {
            IPv6Address netmask = IPv6Address.getNetmask(i);
            tests.add(testIsValidNetmask(netmask, true));
            tests.add(testIsValidNetmask(netmask.previous(), false));
            tests.add(testIsValidNetmask(netmask.next(), false));
        }
        IPv6Address netmask = IPv6Address.getNetmask(127);
        tests.add(testIsValidNetmask(netmask, true));
        tests.add(testIsValidNetmask(netmask.previous(), false));
        // netmask.next() is IPv6ddress.MAX_VALUE
        tests.add(testIsValidNetmask(netmask.next(), true));
        return tests.stream().toArray(DynamicTest[]::new);
    }

    private DynamicTest testIsValidNetmask(IPv6Address address, boolean expected) {
        return dynamicTest(address.toString(), () -> assertEquals(expected, address.isValidNetmask()));
    }

    @TestFactory
    public DynamicTest[] testIsIPv6Address() {
        return new DynamicTest[] {
                testIsIPv6Address(null, false),
                testIsIPv6Address("", false),
                testIsIPv6Address("::1", true),
                testIsIPv6Address("::", true),
                testIsIPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
                testIsIPv6Address("1234:5678:90ab:cdef:3456:7890:abcd:ef12", true),
                testIsIPv6Address("1234:5678:90ab::cdef", true),
                testIsIPv6Address("::192.168.0.1", true),
                testIsIPv6Address("12345:6789:0abc:def3:4567:890a:bcde:f123", false),
                testIsIPv6Address("1234:5678:90ab:cdef:3456:7890:abcd:ef123", false),
        };
    }

    private DynamicTest testIsIPv6Address(String s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv6Address.isIPv6Address(s)));
    }

    @TestFactory
    public DynamicTest[] testIfValidIPv6Address() {
        return new DynamicTest[] {
                testIfValidIPv6Address(null, null),
                testIfValidIPv6Address("12345:6789:0abc:def3:4567:890a:bcde:f123", null),
                testIfValidIPv6Address("1234:5678:90ab:cdef:3456:7890:abcd:ef123", null),
                testIfValidIPv6Address("::1", IPv6Address.LOCALHOST),
        };
    }

    private DynamicTest testIfValidIPv6Address(String s, IPv6Address expected) {
        return dynamicTest(String.valueOf(s), () -> {
            testIfValidIPv6Address(s, expected, true);
            testIfValidIPv6Address(s, expected, false);
        });
    }

    @SuppressWarnings("unchecked")
    private void testIfValidIPv6Address(String s, IPv6Address expected, boolean testResult) {
        Predicate<? super IPAddress<?>> predicate = mock(Predicate.class);
        when(predicate.test(any())).thenReturn(testResult);

        boolean result = IPv6Address.ifValidIPv6Address(predicate).test(s);
        if (expected != null) {
            assertEquals(testResult, result);
            verify(predicate).test(expected);
        } else {
            assertEquals(false, result);
        }
        verifyNoMoreInteractions(predicate);
    }
}
