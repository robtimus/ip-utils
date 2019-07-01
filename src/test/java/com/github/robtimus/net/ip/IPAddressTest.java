/*
 * IPAddressTest.java
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class IPAddressTest {

    @TestFactory
    public DynamicTest[] testValueOfByteArray() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPAddress.valueOf((byte[]) null))),
                testValueOfByteArray(new byte[] { 0x12, 0x34, 0x56, 0x78 }, IPv4Address.valueOf(0x12345678)),
                testValueOfByteArray(new byte[] { 0, 0, 0, 0 }, IPv4Address.MIN_VALUE),
                testValueOfByteArray(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255 }, IPv4Address.MAX_VALUE),
                testValueOfByteArray(new byte[] {
                        0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
                        0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 0x12
                }, IPv6Address.valueOf(0x1234567890ABCDEFL, 0x34567890ABCDEF12L)),
                testValueOfByteArray(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, IPv6Address.MIN_VALUE),
                testValueOfByteArray(new byte[] {
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255
                }, IPv6Address.MAX_VALUE),
                testValueOfByteArrayOfInvalidLength(new byte[0]),
                testValueOfByteArrayOfInvalidLength(new byte[3]),
                testValueOfByteArrayOfInvalidLength(new byte[5]),
                testValueOfByteArrayOfInvalidLength(new byte[15]),
                testValueOfByteArrayOfInvalidLength(new byte[17]),
        };
    }

    private DynamicTest testValueOfByteArray(byte[] address, IPAddress<?> expected) {
        return dynamicTest(Arrays.toString(address), () -> assertEquals(expected, IPAddress.valueOf(address)));
    }

    private DynamicTest testValueOfByteArrayOfInvalidLength(byte[] address) {
        return dynamicTest(Arrays.toString(address), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPAddress.valueOf(address));
            assertEquals(Messages.IPAddress.invalidArraySize.get(address.length), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testValueOfCharSequence() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPAddress.valueOf((CharSequence) null))),
                testValueOfCharSequence("127.0.0.1", IPv4Address.LOCALHOST),
                testValueOfCharSequence("0.0.0.0", IPv4Address.MIN_VALUE),
                testValueOfCharSequence("255.255.255.255", IPv4Address.MAX_VALUE),
                testValueOfCharSequence("12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                testValueOfCharSequence("::1", IPv6Address.LOCALHOST),
                testValueOfCharSequence("::", IPv6Address.MIN_VALUE),
                testValueOfCharSequence("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),
                testValueOfCharSequence("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testValueOfCharSequence("1234:5678:90ab::cdef", IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF)),
                testValueOfCharSequence("::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1)),
                // Just four invalid cases. The parsing has its own tests.
                testValueOfInvalidCharSequence("123.456.789.0"),
                testValueOfInvalidCharSequence("12.34.56.789"),
                testValueOfInvalidCharSequence("12345:6789:0abc:def3:4567:890a:bcde:f123"),
                testValueOfInvalidCharSequence("1234:5678:90ab:cdef:3456:7890:abcd:ef123"),
        };
    }

    private DynamicTest testValueOfCharSequence(String address, IPAddress<?> expected) {
        return dynamicTest(address, () -> assertEquals(expected, IPAddress.valueOf(address)));
    }

    private DynamicTest testValueOfInvalidCharSequence(String address) {
        return dynamicTest(address, () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPAddress.valueOf(address));
            assertEquals(Messages.IPAddress.invalidIPAddress.get(address), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testTryValueOf() {
        return new DynamicTest[] {
                testTryValueOf(null, Optional.empty()),
                testTryValueOf("", Optional.empty()),
                testTryValueOf("127.0.0.1", Optional.of(IPv4Address.LOCALHOST)),
                testTryValueOf("0.0.0.0", Optional.of(IPv4Address.MIN_VALUE)),
                testTryValueOf("255.255.255.255", Optional.of(IPv4Address.MAX_VALUE)),
                testTryValueOf("12.34.56.78", Optional.of(IPv4Address.valueOf(12, 34, 56, 78))),
                testTryValueOf("::1", Optional.of(IPv6Address.LOCALHOST)),
                testTryValueOf("::", Optional.of(IPv6Address.MIN_VALUE)),
                testTryValueOf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Optional.of(IPv6Address.MAX_VALUE)),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        Optional.of(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12))),
                testTryValueOf("1234:5678:90ab::cdef", Optional.of(IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF))),
                testTryValueOf("::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1))),
                // Just four invalid cases. The parsing has its own tests.
                testTryValueOf("123.456.789.0", Optional.empty()),
                testTryValueOf("12.34.56.789", Optional.empty()),
                testTryValueOf("12345:6789:0abc:def3:4567:890a:bcde:f123", Optional.empty()),
                testTryValueOf("1234:5678:90ab:cdef:3456:7890:abcd:ef123", Optional.empty()),
        };
    }

    private DynamicTest testTryValueOf(String address, Optional<IPAddress<?>> expected) {
        String displayName = String.valueOf(address);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPAddress.tryValueOf(address)));
    }

    @TestFactory
    public DynamicTest[] testValueOfInetAddress() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPAddress.valueOf((InetAddress) null))),
                testValueOfInetAddress("127.0.0.1", IPv4Address.LOCALHOST),
                testValueOfInetAddress("0.0.0.0", IPv4Address.MIN_VALUE),
                testValueOfInetAddress("255.255.255.255", IPv4Address.MAX_VALUE),
                testValueOfInetAddress("12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                testValueOfInetAddress("::1", IPv6Address.LOCALHOST),
                testValueOfInetAddress("::", IPv6Address.MIN_VALUE),
                testValueOfInetAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),
                testValueOfInetAddress("1234:5678:90ab:cdef:3456:7890:abcd:ef12",
                        IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0xCDEF, 0x3456, 0x7890, 0xABCD, 0xEF12)),
                testValueOfInetAddress("1234:5678:90ab::cdef", IPv6Address.valueOf(0x1234, 0x5678, 0x90AB, 0, 0, 0, 0, 0xCDEF)),
                testValueOfInetAddress("::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 1)),
        };
    }

    private DynamicTest testValueOfInetAddress(String address, IPAddress<?> expected) {
        return dynamicTest(address, () -> assertEquals(expected, IPAddress.valueOf(InetAddress.getByName(address))));
    }

    @TestFactory
    public DynamicTest[] testIsIPAddress() {
        return new DynamicTest[] {
                testIsIPAddress(null, false),
                testIsIPAddress("", false),
                testIsIPAddress("127.0.0.1", true),
                testIsIPAddress("0.0.0.0", true),
                testIsIPAddress("255.255.255.255", true),
                testIsIPAddress("12.34.56.78", true),
                testIsIPAddress("123.456.789.0", false),
                testIsIPAddress("::1", true),
                testIsIPAddress("::", true),
                testIsIPAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
                testIsIPAddress("1234:5678:90ab:cdef:3456:7890:abcd:ef12", true),
                testIsIPAddress("1234:5678:90ab::cdef", true),
                testIsIPAddress("::192.168.0.1", true),
                testIsIPAddress("12345:6789:0abc:def3:4567:890a:bcde:f123", false),
                testIsIPAddress("1234:5678:90ab:cdef:3456:7890:abcd:ef123", false),
        };
    }

    private DynamicTest testIsIPAddress(String s, boolean expected) {
        String displayName = String.valueOf(s);
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPAddress.isIPAddress(s)));
    }

    @TestFactory
    public DynamicTest[] testIfValidIPAddress() {
        return new DynamicTest[] {
                testIfValidIPAddress(null, null),
                testIfValidIPAddress("123.456.789.0", null),
                testIfValidIPAddress("12.34.56.789", null),
                testIfValidIPAddress("127.0.0.1", IPv4Address.LOCALHOST),
                testIfValidIPAddress("12345:6789:0abc:def3:4567:890a:bcde:f123", null),
                testIfValidIPAddress("1234:5678:90ab:cdef:3456:7890:abcd:ef123", null),
                testIfValidIPAddress("::1", IPv6Address.LOCALHOST),
        };
    }

    private DynamicTest testIfValidIPAddress(String s, IPAddress<?> expected) {
        return dynamicTest(String.valueOf(s), () -> {
            testIfValidIPAddress(s, expected, true);
            testIfValidIPAddress(s, expected, false);
        });
    }

    @SuppressWarnings("unchecked")
    private void testIfValidIPAddress(String s, IPAddress<?> expected, boolean testResult) {
        Predicate<? super IPAddress<?>> predicate = mock(Predicate.class);
        when(predicate.test(any())).thenReturn(testResult);

        boolean result = IPAddress.ifValidIPAddress(predicate).test(s);
        if (expected != null) {
            assertEquals(testResult, result);
            verify(predicate).test(expected);
        } else {
            assertEquals(false, result);
        }
        verifyNoMoreInteractions(predicate);
    }
}
