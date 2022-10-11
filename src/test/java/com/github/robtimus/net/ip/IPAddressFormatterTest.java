/*
 * IPAddressFormatterTest.java
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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.text.ParseException;
import java.text.ParsePosition;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import com.github.robtimus.net.ip.IPAddressFormatter.Builder;

@SuppressWarnings("nls")
class IPAddressFormatterTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("ipv6")
    void testIPv6(@SuppressWarnings("unused") String displayName, Builder<IPv6Address> builder, IPv6Address address, String expected) {
        IPAddressFormatter<IPv6Address> formatter = builder.build();
        assertEquals(expected, formatter.format(address));
    }

    static Arguments[] testIPv6() {
        IPv6Address address = IPv6Address.valueOf(1, 2, 3, 0, 0, 0, 0xFFAB, 0x1234);
        return new Arguments[] {
                arguments("unmodified", IPAddressFormatter.ipv6(), address, "1:2:3::ffab:1234"),
                arguments("withDefaults", IPAddressFormatter.ipv6().withDefaults(), address, "1:2:3::ffab:1234"),
                // others are tested through nested class IPv6
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    @DisplayName("anyVersion")
    void testAnyVersion(@SuppressWarnings("unused") String displayName, Builder<IPAddress<?>> builder, IPv6Address ipv6Address,
            String expectedIPv6) {

        IPAddressFormatter<IPAddress<?>> formatter = builder.build();
        assertEquals("12.34.56.78", formatter.format(IPv4Address.valueOf(12, 34, 56, 78)));
        assertEquals(expectedIPv6, formatter.format(ipv6Address));
    }

    static Arguments[] testAnyVersion() {
        IPv6Address ipv6Address = IPv6Address.valueOf(1, 2, 3, 0, 0, 0, 0xFFAB, 0x1234);
        return new Arguments[] {
                arguments("unmodified", IPAddressFormatter.anyVersion(), ipv6Address, "1:2:3::ffab:1234"),
                arguments("withDefaults", IPAddressFormatter.anyVersion().withDefaults(), ipv6Address, "1:2:3::ffab:1234"),
                // others are tested through nested class AnyVersion
        };
    }

    @Nested
    @DisplayName("Builder")
    class BuilderTest {

        @Test
        @DisplayName("transform")
        void testTransform() {
            IPAddressFormatter.Builder<IPv6Address> builder = IPAddressFormatter.ipv6();
            @SuppressWarnings("unchecked")
            Function<IPAddressFormatter.Builder<?>, String> f = mock(Function.class);
            when(f.apply(builder)).thenReturn("result");

            assertEquals("result", builder.transform(f));
            verify(f).apply(builder);
            verifyNoMoreInteractions(f);
        }
    }

    @Nested
    class IPv4 {

        @TestFactory
        @DisplayName("format(IPv4Address)")
        DynamicTest[] testFormatIPv4Address() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.format((IPv4Address) null))),
                    testFormatIPv4Address(formatter, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testFormatIPv4Address(formatter, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testFormatIPv4Address(formatter, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testFormatIPv4Address(formatter, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testFormatIPv4Address(formatter, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),
            };
        }

        private DynamicTest testFormatIPv4Address(IPAddressFormatter<IPv4Address> formatter, IPv4Address address, String expected) {
            return dynamicTest(address.toString(), () -> assertEquals(expected, formatter.format(address)));
        }

        @TestFactory
        @DisplayName("format(byte[])")
        DynamicTest[] testFormatBytes() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null))),
                    testFormatBytes(formatter, new byte[] { 127, 0, 0, 1, }, "127.0.0.1"),
                    testFormatBytes(formatter, new byte[] { 0, 0, 0, 0, }, "0.0.0.0"),
                    testFormatBytes(formatter, new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }, "255.255.255.255"),
                    testFormatBytes(formatter, new byte[] { 123, (byte) 234, (byte) 210, 109, }, "123.234.210.109"),
                    testFormatBytes(formatter, new byte[] { 1, 2, 3, 4, }, "1.2.3.4"),
                    testFormatBytesOfInvalidLength(formatter, 0),
                    testFormatBytesOfInvalidLength(formatter, 3),
                    testFormatBytesOfInvalidLength(formatter, 5),
                    testFormatBytesOfInvalidLength(formatter, 16),
            };
        }

        private DynamicTest testFormatBytes(IPAddressFormatter<IPv4Address> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> assertEquals(expected, formatter.format(address)));
        }

        private DynamicTest testFormatBytesOfInvalidLength(IPAddressFormatter<IPv4Address> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        @TestFactory
        @DisplayName("append(IPv4Address)")
        DynamicTest[] testAppendIPv4Address() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null",
                            () -> assertThrows(NullPointerException.class, () -> formatter.append((IPv4Address) null, new StringWriter()))),
                    testAppendIPv4Address(formatter, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testAppendIPv4Address(formatter, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testAppendIPv4Address(formatter, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testAppendIPv4Address(formatter, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testAppendIPv4Address(formatter, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),
            };
        }

        private DynamicTest testAppendIPv4Address(IPAddressFormatter<IPv4Address> formatter, IPv4Address address, String expected) {
            return dynamicTest(address.toString(), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        @TestFactory
        @DisplayName("append(byte[])")
        DynamicTest[] testAppendBytes() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.append((byte[]) null, new StringWriter()))),
                    testAppendBytes(formatter, new byte[] { 127, 0, 0, 1, }, "127.0.0.1"),
                    testAppendBytes(formatter, new byte[] { 0, 0, 0, 0, }, "0.0.0.0"),
                    testAppendBytes(formatter, new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }, "255.255.255.255"),
                    testAppendBytes(formatter, new byte[] { 123, (byte) 234, (byte) 210, 109, }, "123.234.210.109"),
                    testAppendBytes(formatter, new byte[] { 1, 2, 3, 4, }, "1.2.3.4"),
                    testAppendBytesOfInvalidLength(formatter, 0),
                    testAppendBytesOfInvalidLength(formatter, 3),
                    testAppendBytesOfInvalidLength(formatter, 5),
                    testAppendBytesOfInvalidLength(formatter, 16),
            };
        }

        private DynamicTest testAppendBytes(IPAddressFormatter<IPv4Address> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        private DynamicTest testAppendBytesOfInvalidLength(IPAddressFormatter<IPv4Address> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                        () -> formatter.append(new byte[length], new StringWriter()));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        // valueOf is tested through IPv4AddressTest.testValueOfCharSequence

        @TestFactory
        @DisplayName("parse(CharSequence) and parse(CharSequence, int, int)")
        DynamicTest[] testParse() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.parse(null));
                        assertThrows(NullPointerException.class, () -> formatter.parse(null, 0, 0));
                    }),
                    testParseInvalid(formatter, "", 0),
                    testParse(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                    testParse(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                    testParse(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                    testParse(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                    testParseInvalid(formatter, ".34.56.78", 0),
                    testParseInvalid(formatter, "12..56.78", 3),
                    testParseInvalid(formatter, "12.34..78", 6),
                    testParseInvalid(formatter, "12.34.56.", 9),
                    testParseInvalid(formatter, "1234.456.789.0", 3),
                    testParseInvalid(formatter, "123.456.789.0", 6),
                    testParseInvalid(formatter, "12.34.56.789", 11),
                    testParseInvalid(formatter, "12.34.56", 8),
            };
        }

        private DynamicTest testParse(IPAddressFormatter<IPv4Address> formatter, String source, IPv4Address expected) {
            return dynamicTest(source, () -> {
                assertEquals(expected, formatter.parse(source));
                assertEquals(expected, formatter.parse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(expected, formatter.parse("z" + source + "z", 1, 1 + source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        private DynamicTest testParseInvalid(IPAddressFormatter<IPv4Address> formatter, String source, int errorIndex) {
            return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                ParseException exception = assertThrows(ParseException.class, () -> formatter.parse(source));
                assertEquals(errorIndex, exception.getErrorOffset());
                assertEquals(Messages.IPv4Address.parseError(source), exception.getMessage());

                exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        @DisplayName("parse(CharSequence, ParsePosition)")
        DynamicTest[] testParseWithPosition() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null, new ParsePosition(0)))),
                    dynamicTest("null position", () -> assertThrows(NullPointerException.class, () -> formatter.parse("127.0.0.1", null))),
                    testParseInvalidWithPosition(formatter, "", 0),
                    testParseWithPosition(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                    testParseWithPosition(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                    testParseWithPosition(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                    testParseWithPosition(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                    testParseInvalidWithPosition(formatter, ".34.56.78", 0),
                    testParseInvalidWithPosition(formatter, "12..56.78", 3),
                    testParseInvalidWithPosition(formatter, "12.34..78", 6),
                    testParseInvalidWithPosition(formatter, "12.34.56.", 9),
                    testParseInvalidWithPosition(formatter, "1234.456.789.0", 3),
                    testParseInvalidWithPosition(formatter, "123.456.789.0", 6),
                    testParseWithPosition(formatter, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78), 11),
                    testParseInvalidWithPosition(formatter, "12.34.56", 8),
            };
        }

        private DynamicTest testParseWithPosition(IPAddressFormatter<IPv4Address> formatter, String source, IPv4Address expected) {
            return testParseWithPosition(formatter, source, expected, source.length());
        }

        private DynamicTest testParseWithPosition(IPAddressFormatter<IPv4Address> formatter, String source, IPv4Address expected, int expectedIndex) {
            return dynamicTest(source, () -> {
                ParsePosition position = new ParsePosition(0);
                IPv4Address address = formatter.parse(source, position);
                assertEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(expectedIndex, position.getIndex());

                String postfix = "z2345";
                position.setIndex(0);
                position.setErrorIndex(-1);
                address = formatter.parse(source + postfix, position);
                assertEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(expectedIndex, position.getIndex());

                String prefix = "12345";
                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                address = formatter.parse(prefix + source + postfix, position);
                assertEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(prefix.length() + expectedIndex, position.getIndex());

                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                address = formatter.parse(prefix + source, position);
                assertEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(prefix.length() + expectedIndex, position.getIndex());
            });
        }

        private DynamicTest testParseInvalidWithPosition(IPAddressFormatter<IPv4Address> formatter, String source, int errorIndex) {
            return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                ParsePosition position = new ParsePosition(0);
                assertNull(formatter.parse(source, position));
                assertEquals(errorIndex, position.getErrorIndex());
                assertEquals(0, position.getIndex());

                String prefix = "12345";
                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                assertNull(formatter.parse(prefix + source, position));
                assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                assertEquals(prefix.length(), position.getIndex());
            });
        }

        @TestFactory
        @DisplayName("tryParse")
        DynamicTest[] testTryParse() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> {
                        assertEquals(Optional.empty(), formatter.tryParse(null));
                        assertEquals(Optional.empty(), formatter.tryParse(null, 0, 0));
                    }),
                    testTryParse(formatter, "", Optional.empty()),
                    testTryParse(formatter, "127.0.0.1", Optional.of(IPv4Address.LOCALHOST)),
                    testTryParse(formatter, "0.0.0.0", Optional.of(IPv4Address.MIN_VALUE)),
                    testTryParse(formatter, "255.255.255.255", Optional.of(IPv4Address.MAX_VALUE)),
                    testTryParse(formatter, "12.34.56.78", Optional.of(IPv4Address.valueOf(12, 34, 56, 78))),
                    testTryParse(formatter, ".34.56.78", Optional.empty()),
                    testTryParse(formatter, "12..56.78", Optional.empty()),
                    testTryParse(formatter, "12.34..78", Optional.empty()),
                    testTryParse(formatter, "12.34.56.", Optional.empty()),
                    testTryParse(formatter, "1234.456.789.0", Optional.empty()),
                    testTryParse(formatter, "123.456.789.0", Optional.empty()),
                    testTryParse(formatter, "12.34.56.789", Optional.empty()),
                    testTryParse(formatter, "12.34.56", Optional.empty()),
            };
        }

        private DynamicTest testTryParse(IPAddressFormatter<IPv4Address> formatter, String source, Optional<IPv4Address> expected) {
            String displayName = String.valueOf(source);
            return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                assertEquals(expected, formatter.tryParse(source));
                assertEquals(expected, formatter.tryParse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(expected, formatter.tryParse("z" + source + "z", 1, 1 + source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, -1));
            });
        }

        @TestFactory
        @DisplayName("parseToBytes(CharSequence) and parseToBytes(CharSequence, int, int)")
        DynamicTest[] testParseToBytes() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null));
                        assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null, 0, 0));
                    }),
                    testParseToBytesInvalid(formatter, "", 0),
                    testParseToBytes(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                    testParseToBytes(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                    testParseToBytes(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }),
                    testParseToBytes(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),
                    testParseToBytesInvalid(formatter, ".34.56.78", 0),
                    testParseToBytesInvalid(formatter, "12..56.78", 3),
                    testParseToBytesInvalid(formatter, "12.34..78", 6),
                    testParseToBytesInvalid(formatter, "12.34.56.", 9),
                    testParseToBytesInvalid(formatter, "1234.456.789.0", 3),
                    testParseToBytesInvalid(formatter, "123.456.789.0", 6),
                    testParseToBytesInvalid(formatter, "12.34.56.789", 11),
                    testParseToBytesInvalid(formatter, "12.34.56", 8),
            };
        }

        private DynamicTest testParseToBytes(IPAddressFormatter<IPv4Address> formatter, String source, byte[] expected) {
            return dynamicTest(source, () -> {
                assertArrayEquals(expected, formatter.parseToBytes(source));
                assertArrayEquals(expected, formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                assertArrayEquals(expected, formatter.parseToBytes("z" + source + "z", 1, 1 + source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, -1));
            });
        }

        private DynamicTest testParseToBytesInvalid(IPAddressFormatter<IPv4Address> formatter, String source, int errorIndex) {
            return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                ParseException exception = assertThrows(ParseException.class, () -> formatter.parseToBytes(source));
                assertEquals(errorIndex, exception.getErrorOffset());
                assertEquals(Messages.IPv4Address.parseError(source), exception.getMessage());

                exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        @DisplayName("parseToBytes(CharSequence, ParsePosition)")
        DynamicTest[] testParseToBytesWithPosition() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null, new ParsePosition(0)))),
                    dynamicTest("null position", () -> assertThrows(NullPointerException.class, () -> formatter.parseToBytes("127.0.0.1", null))),
                    testParseToBytesInvalidWithPosition(formatter, "", 0),
                    testParseToBytesWithPosition(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                    testParseToBytesWithPosition(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                    testParseToBytesWithPosition(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255}),
                    testParseToBytesWithPosition(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),
                    testParseToBytesInvalidWithPosition(formatter, ".34.56.78", 0),
                    testParseToBytesInvalidWithPosition(formatter, "12..56.78", 3),
                    testParseToBytesInvalidWithPosition(formatter, "12.34..78", 6),
                    testParseToBytesInvalidWithPosition(formatter, "12.34.56.", 9),
                    testParseToBytesInvalidWithPosition(formatter, "1234.456.789.0", 3),
                    testParseToBytesInvalidWithPosition(formatter, "123.456.789.0", 6),
                    testParseToBytesWithPosition(formatter, "12.34.56.789", new byte[] { 12, 34, 56, 78, }, 11),
                    testParseToBytesInvalidWithPosition(formatter, "12.34.56", 8),
            };
        }

        private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPv4Address> formatter, String source, byte[] expected) {
            return testParseToBytesWithPosition(formatter, source, expected, source.length());
        }

        private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPv4Address> formatter, String source,
                byte[] expected, int expectedIndex) {

            return dynamicTest(source, () -> {
                ParsePosition position = new ParsePosition(0);
                byte[] address = formatter.parseToBytes(source, position);
                assertArrayEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(expectedIndex, position.getIndex());

                String postfix = "z2345";
                position.setIndex(0);
                position.setErrorIndex(-1);
                address = formatter.parseToBytes(source + postfix, position);
                assertArrayEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(expectedIndex, position.getIndex());

                String prefix = "12345";
                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                address = formatter.parseToBytes(prefix + source + postfix, position);
                assertArrayEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(prefix.length() + expectedIndex, position.getIndex());

                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                address = formatter.parseToBytes(prefix + source, position);
                assertArrayEquals(expected, address);
                assertEquals(-1, position.getErrorIndex());
                assertEquals(prefix.length() + expectedIndex, position.getIndex());
            });
        }

        private DynamicTest testParseToBytesInvalidWithPosition(IPAddressFormatter<IPv4Address> formatter, String source, int errorIndex) {
            return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                ParsePosition position = new ParsePosition(0);
                assertNull(formatter.parseToBytes(source, position));
                assertEquals(errorIndex, position.getErrorIndex());
                assertEquals(0, position.getIndex());

                String prefix = "12345";
                position.setIndex(prefix.length());
                position.setErrorIndex(-1);
                assertNull(formatter.parseToBytes(prefix + source, position));
                assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                assertEquals(prefix.length(), position.getIndex());
            });
        }

        @TestFactory
        @DisplayName("tryParseToBytes")
        DynamicTest[] testTryParseToBytes() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> {
                        assertEquals(Optional.empty(), formatter.tryParseToBytes(null));
                        assertEquals(Optional.empty(), formatter.tryParseToBytes(null, 0, 0));
                    }),
                    testTryParseToBytesEmptyOptional(formatter, ""),
                    testTryParseToBytes(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                    testTryParseToBytes(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                    testTryParseToBytes(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }),
                    testTryParseToBytes(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),
                    testTryParseToBytesEmptyOptional(formatter, ".34.56.78"),
                    testTryParseToBytesEmptyOptional(formatter, "12..56.78"),
                    testTryParseToBytesEmptyOptional(formatter, "12.34..78"),
                    testTryParseToBytesEmptyOptional(formatter, "12.34.56."),
                    testTryParseToBytesEmptyOptional(formatter, "1234.456.789.0"),
                    testTryParseToBytesEmptyOptional(formatter, "123.456.789.0"),
                    testTryParseToBytesEmptyOptional(formatter, "12.34.56.789"),
                    testTryParseToBytesEmptyOptional(formatter, "12.34.56"),
            };
        }

        private DynamicTest testTryParseToBytes(IPAddressFormatter<IPv4Address> formatter, String source, byte[] expected) {
            return dynamicTest(source, () -> {
                assertArrayEquals(expected, formatter.tryParseToBytes(source).get());
                assertArrayEquals(expected, formatter.tryParseToBytes("1" + source + "1", 1, 1 + source.length()).get());
                assertArrayEquals(expected, formatter.tryParseToBytes("z" + source + "z", 1, 1 + source.length()).get());
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
            });
        }

        private DynamicTest testTryParseToBytesEmptyOptional(IPAddressFormatter<IPv4Address> formatter, String source) {
            String displayName = String.valueOf(source);
            return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                assertEquals(Optional.empty(), formatter.tryParseToBytes(source));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
            });
        }

        @Nested
        @DisplayName("asFormat")
        class AsFormat {

            @TestFactory
            @DisplayName("format")
            DynamicTest[] testFormat() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                return new DynamicTest[] {
                        testFormat(format, IPv4Address.LOCALHOST, "127.0.0.1"),
                        testFormat(format, IPv4Address.MIN_VALUE, "0.0.0.0"),
                        testFormat(format, IPv4Address.MAX_VALUE, "255.255.255.255"),
                        testFormat(format, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                        testFormat(format, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),
                        testFormat(format, new byte[] { 127, 0, 0, 1, }, "127.0.0.1"),
                        testFormat(format, new byte[] { 0, 0, 0, 0, }, "0.0.0.0"),
                        testFormat(format, new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }, "255.255.255.255"),
                        testFormat(format, new byte[] { 123, (byte) 234, (byte) 210, 109, }, "123.234.210.109"),
                        testFormat(format, new byte[] { 1, 2, 3, 4, }, "1.2.3.4"),
                        testFormatBytesOfInvalidLength(format, 0),
                        testFormatBytesOfInvalidLength(format, 3),
                        testFormatBytesOfInvalidLength(format, 5),
                        testFormatBytesOfInvalidLength(format, 16),
                        testFormatUnsupportedObject(format, null),
                        testFormatUnsupportedObject(format, IPv6Address.LOCALHOST),
                        testFormatUnsupportedObject(format, "127.0.0.1"),
                };
            }

            private DynamicTest testFormat(IPAddressFormat<IPv4Address> format, Object object, String expected) {
                return dynamicTest(object.toString(), () -> assertEquals(expected, format.format(object)));
            }

            private DynamicTest testFormat(IPAddressFormat<IPv4Address> format, byte[] array, String expected) {
                return dynamicTest(Arrays.toString(array), () -> assertEquals(expected, format.format(array)));
            }

            private DynamicTest testFormatBytesOfInvalidLength(IPAddressFormat<IPv4Address> format, int length) {
                return dynamicTest(String.format("invalid length: %d", length), () -> {
                    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> format.format(new byte[length]));
                    assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
                });
            }

            private DynamicTest testFormatUnsupportedObject(IPAddressFormat<IPv4Address> format, Object object) {
                return dynamicTest(String.format("unsupported: %s", object), () -> {
                    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> format.format(object));
                    assertEquals(Messages.IPAddressFormat.unformattableObject(object), exception.getMessage());
                });
            }

            @TestFactory
            @DisplayName("parseObject(String)")
            DynamicTest[] testParseObject() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null))),
                        testParseObjectInvalid(format, "", 0),
                        testParseObject(format, "127.0.0.1", IPv4Address.LOCALHOST),
                        testParseObject(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testParseObject(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testParseObject(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                        // parsing stops after 78
                        testParseObject(format, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78)),
                        testParseObjectInvalid(format, ".34.56.78", 0),
                        testParseObjectInvalid(format, "12..56.78", 3),
                        testParseObjectInvalid(format, "12.34..78", 6),
                        testParseObjectInvalid(format, "12.34.56.", 9),
                        testParseObjectInvalid(format, "1234.456.789.0", 3),
                        testParseObjectInvalid(format, "123.456.789.0", 6),
                        testParseObjectInvalid(format, "12.34.56", 8),
                };
            }

            private DynamicTest testParseObject(IPAddressFormat<IPv4Address> format, String source, IPv4Address expected) {
                return dynamicTest(source, () -> assertEquals(expected, format.parseObject(source)));
            }

            private DynamicTest testParseObjectInvalid(IPAddressFormat<IPv4Address> format, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> format.parseObject(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                });
            }

            @TestFactory
            @DisplayName("parseObject(String, ParsePosition)")
            DynamicTest[] testParseObjectWithPosition() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null, new ParsePosition(0)))),
                        dynamicTest("null position", () -> assertThrows(NullPointerException.class, () -> format.parseObject("127.0.0.1", null))),
                        testParseObjectInvalidWithPosition(format, "", 0),
                        testParseObjectWithPosition(format, "127.0.0.1", IPv4Address.LOCALHOST),
                        testParseObjectWithPosition(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testParseObjectWithPosition(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testParseObjectWithPosition(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                        testParseObjectInvalidWithPosition(format, ".34.56.78", 0),
                        testParseObjectInvalidWithPosition(format, "12..56.78", 3),
                        testParseObjectInvalidWithPosition(format, "12.34..78", 6),
                        testParseObjectInvalidWithPosition(format, "12.34.56.", 9),
                        testParseObjectInvalidWithPosition(format, "1234.456.789.0", 3),
                        testParseObjectInvalidWithPosition(format, "123.456.789.0", 6),
                        testParseObjectWithPosition(format, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78), 11),
                        testParseObjectInvalidWithPosition(format, "12.34.56", 8),
                };
            }

            private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPv4Address> format, String source, IPv4Address expected) {
                return testParseObjectWithPosition(format, source, expected, source.length());
            }

            private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPv4Address> format, String source, IPv4Address expected,
                    int expectedIndex) {

                return dynamicTest(source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    IPv4Address address = format.parseObject(source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String postfix = "z2345";
                    position.setIndex(0);
                    position.setErrorIndex(-1);
                    address = format.parseObject(source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = format.parseObject(prefix + source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());

                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = format.parseObject(prefix + source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());
                });
            }

            private DynamicTest testParseObjectInvalidWithPosition(IPAddressFormat<IPv4Address> format, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    assertNull(format.parseObject(source, position));
                    assertEquals(errorIndex, position.getErrorIndex());
                    assertEquals(0, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    assertNull(format.parseObject(prefix + source, position));
                    assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                    assertEquals(prefix.length(), position.getIndex());
                });
            }

            // parse(CharSequence source, ParsePosition position) is tested through parseObject

            @TestFactory
            @DisplayName("parse(CharSequence)")
            DynamicTest[] testParse() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parse(null))),
                        testParseInvalid(format, "", 0),
                        testParse(format, "127.0.0.1", IPv4Address.LOCALHOST),
                        testParse(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testParse(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testParse(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                        testParseInvalid(format, ".34.56.78", 0),
                        testParseInvalid(format, "12..56.78", 3),
                        testParseInvalid(format, "12.34..78", 6),
                        testParseInvalid(format, "12.34.56.", 9),
                        testParseInvalid(format, "1234.456.789.0", 3),
                        testParseInvalid(format, "123.456.789.0", 6),
                        testParseInvalid(format, "12.34.56.789", 11),
                        testParseInvalid(format, "12.34.56", 8),
                };
            }

            private DynamicTest testParse(IPAddressFormat<IPv4Address> format, String source, IPv4Address expected) {
                return dynamicTest(source, () -> assertEquals(expected, format.parse(source)));
            }

            private DynamicTest testParseInvalid(IPAddressFormat<IPv4Address> format, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> format.parse(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                });
            }

            @TestFactory
            @DisplayName("equals")
            DynamicTest[] testEquals() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                return new DynamicTest[] {
                        testEquals(format, format, true),
                        testEquals(format, null, false),
                        testEquals(format, IPAddressFormatter.ipv6WithDefaults().asFormat(), false),
                };
            }

            private DynamicTest testEquals(IPAddressFormat<IPv4Address> format, Object object, boolean expectEquals) {
                BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
                return dynamicTest(String.valueOf(object), () -> equalsCheck.accept(format, object));
            }

            @Test
            @DisplayName("toString")
            void testToString() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                assertEquals(IPAddressFormat.class.getName() + "#IPv4", format.toString());
            }

            @Test
            @DisplayName("clone")
            @SuppressWarnings({ "deprecation", "unchecked" })
            void testClone() {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                IPAddressFormat<IPv4Address> clone = (IPAddressFormat<IPv4Address>) format.clone();
                assertNotSame(format, clone);
                assertEquals(format.formatter(), clone.formatter());
                assertEquals(format, clone);
                assertEquals(format.hashCode(), clone.hashCode());
            }

            @Test
            @DisplayName("serialization")
            void testSerialization() throws IOException, ClassNotFoundException {
                IPAddressFormat<IPv4Address> format = IPAddressFormatter.ipv4().asFormat();
                IPAddressFormat<IPv4Address> copy = assertSerializable(format);
                assertSame(format, copy);
            }
        }

        @TestFactory
        @DisplayName("isValid")
        DynamicTest[] testIsValid() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertEquals(false, formatter.isValid(null, 0, 0))),
                    testIsValid(formatter, "", false),
                    testIsValid(formatter, "127.0.0.1", true),
                    testIsValid(formatter, "0.0.0.0", true),
                    testIsValid(formatter, "255.255.255.255", true),
                    testIsValid(formatter, "12.34.56.78", true),
                    testIsValid(formatter, ".34.56.78", false),
                    testIsValid(formatter, "12..56.78", false),
                    testIsValid(formatter, "12.34..78", false),
                    testIsValid(formatter, "12.34.56.", false),
                    testIsValid(formatter, "1234.456.789.0", false),
                    testIsValid(formatter, "123.456.789.0", false),
                    testIsValid(formatter, "12.34.56.789", false),
                    testIsValid(formatter, "12.34.56", false),
            };
        }

        private DynamicTest testIsValid(IPAddressFormatter<IPv4Address> formatter, String source, boolean expected) {
            String displayName = String.valueOf(source);
            return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                assertEquals(expected, formatter.isValid(source, 0, source.length()));
                assertEquals(expected, formatter.isValid("1" + source + "1", 1, 1 + source.length()));
                assertEquals(expected, formatter.isValid("z" + source + "z", 1, 1 + source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, -1));
            });
        }

        @TestFactory
        @DisplayName("ifValid")
        DynamicTest[] testTestIfValid() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            return new DynamicTest[] {
                    testTestIfValid(formatter, null, null),
                    testTestIfValid(formatter, "", null),
                    testTestIfValid(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                    testTestIfValid(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                    testTestIfValid(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                    testTestIfValid(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                    testTestIfValid(formatter, ".34.56.78", null),
                    testTestIfValid(formatter, "12..56.78", null),
                    testTestIfValid(formatter, "12.34..78", null),
                    testTestIfValid(formatter, "12.34.56.", null),
                    testTestIfValid(formatter, "1234.456.789.0", null),
                    testTestIfValid(formatter, "123.456.789.0", null),
                    testTestIfValid(formatter, "12.34.56.789", null),
                    testTestIfValid(formatter, "12.34.56", null),
            };
        }

        private DynamicTest testTestIfValid(IPAddressFormatter<IPv4Address> formatter, String source, IPv4Address expected) {
            String displayName = String.valueOf(source);
            return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                testTestIfValid(formatter, source, expected, true);
                testTestIfValid(formatter, source, expected, false);
            });
        }

        @SuppressWarnings("unchecked")
        private void testTestIfValid(IPAddressFormatter<IPv4Address> formatter, String source, IPv4Address expected, boolean testResult) {
            Predicate<? super IPv4Address> predicate = mock(Predicate.class);
            when(predicate.test(any())).thenReturn(testResult);

            boolean result = formatter.testIfValid(source, predicate);
            if (expected != null) {
                assertEquals(testResult, result);
                verify(predicate).test(expected);
            } else {
                assertEquals(false, result);
            }
            verifyNoMoreInteractions(predicate);
        }

        @Test
        @DisplayName("toString")
        void testToString() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            assertEquals(IPAddressFormatter.class.getName() + "#IPv4", formatter.toString());
        }
    }

    @Nested
    class IPv6 {

        private final IPv6Address testAddress1 = IPv6Address.valueOf(0L, 0L);
        private final IPv6Address testAddress2 = IPv6Address.valueOf(0L, 1L);
        private final IPv6Address testAddress3 = IPv6Address.valueOf(0x0001000000000000L, 0L);
        // no zeroes sections
        private final IPv6Address testAddress4 = IPv6Address.valueOf(0x0123045607890100L, 0xABCDEF0010000001L);
        // one zeroes sections
        private final IPv6Address testAddress5 = IPv6Address.valueOf(0x1200000000000000L, 0x0000123400010001L);
        // two zeroes sections, the first one being the longest
        private final IPv6Address testAddress6 = IPv6Address.valueOf(0x1200000000000000L, 0x0000123400000000L);
        // two zeroes sections, the second one being the longest
        private final IPv6Address testAddress7 = IPv6Address.valueOf(0x1200000000001234L, 0x5678000000000000L);

        @TestFactory
        @DisplayName("format specific")
        DynamicContainer[] testFormatSpecific() {
            return new DynamicContainer[] {
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "::", "::1", "1::", "123:456:789:100:abcd:ef00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:abcd:ef00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "::", "::1", "1::", "123:456:789:100:ABCD:EF00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:ABCD:EF00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:abcd:ef00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:abcd:ef00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:ABCD:EF00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:ABCD:EF00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:abcd:ef00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:abcd:ef00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:abcd:ef00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:abcd:ef00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:ABCD:EF00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:ABCD:EF00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:ABCD:EF00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:ABCD:EF00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]"),
            };
        }

        private DynamicContainer testFormatSpecific(Builder<IPv6Address> builder, String expectedToStringPostfix,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            IPAddressFormatter<IPv6Address> formatter = builder.build();
            String displayName = formatter.toString().replaceAll(".*\\[(.*)\\]", "$1");

            DynamicNode[] nodes = {
                    testFormatSpecificFormatIPv6Address(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificFormatBytes(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAppendIPv6Address(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAppendBytes(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAsFormat(formatter, expectedToStringPostfix, expectedFormatted1, expectedFormatted2, expectedFormatted3,
                            expectedFormatted4, expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificToString(formatter, expectedToStringPostfix),
            };
            return dynamicContainer(displayName, Arrays.asList(nodes));
        }

        private DynamicContainer testFormatSpecificFormatIPv6Address(IPAddressFormatter<IPv6Address> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.format((IPv6Address) null));
                        assertThrows(NullPointerException.class, () -> formatter.format((IPv6Address) null, new StringBuilder()));
                        assertThrows(NullPointerException.class, () -> formatter.format((IPv6Address) null, new StringBuffer()));
                    }),
                    dynamicTest("null StringBuilder",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(IPv6Address.LOCALHOST, (StringBuilder) null))),
                    dynamicTest("null StringBuffer",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(IPv6Address.LOCALHOST, (StringBuilder) null))),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress1, expectedFormatted1),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress2, expectedFormatted2),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress3, expectedFormatted3),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress4, expectedFormatted4),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress5, expectedFormatted5),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress6, expectedFormatted6),
                    testFormatSpecificFormatIPv6Address(formatter, testAddress7, expectedFormatted7),
            };
            return dynamicContainer("format(IPv6Address)", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificFormatIPv6Address(IPAddressFormatter<IPv6Address> formatter, IPv6Address address, String expected) {
            return dynamicTest(address.toString(), () -> {
                assertEquals(expected, formatter.format(address));
                assertEquals(expected, formatter.format(address, new StringBuilder()).toString());
                assertEquals(expected, formatter.format(address, new StringBuffer()).toString());
            });
        }

        private DynamicContainer testFormatSpecificFormatBytes(IPAddressFormatter<IPv6Address> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null));
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null, new StringBuilder()));
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null, new StringBuffer()));
                    }),
                    dynamicTest("null StringBuilder",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(new byte[16], (StringBuilder) null))),
                    dynamicTest("null StringBuffer",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(new byte[16], (StringBuilder) null))),
                    testFormatSpecificFormatBytes(formatter, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificFormatBytes(formatter, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificFormatBytes(formatter, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificFormatBytes(formatter, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificFormatBytes(formatter, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificFormatBytes(formatter, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificFormatBytes(formatter, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 0),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 4),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 15),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 17),
            };
            return dynamicContainer("format(byte[])", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificFormatBytes(IPAddressFormatter<IPv6Address> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> {
                assertEquals(expected, formatter.format(address));
                assertEquals(expected, formatter.format(address, new StringBuilder()).toString());
                assertEquals(expected, formatter.format(address, new StringBuffer()).toString());
            });
        }

        private DynamicTest testFormatSpecificFormatBytesOfInvalidLength(IPAddressFormatter<IPv6Address> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length], new StringBuilder()));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAppendIPv6Address(IPAddressFormatter<IPv6Address> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null",
                            () -> assertThrows(NullPointerException.class, () -> formatter.append((IPv6Address) null, new StringWriter()))),
                    dynamicTest("null Appender", () -> assertThrows(NullPointerException.class, () -> formatter.append(IPv6Address.LOCALHOST, null))),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress1, expectedFormatted1),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress2, expectedFormatted2),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress3, expectedFormatted3),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress4, expectedFormatted4),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress5, expectedFormatted5),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress6, expectedFormatted6),
                    testFormatSpecificAppendIPv6Address(formatter, testAddress7, expectedFormatted7),
            };
            return dynamicContainer("append(IPv6Address)", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAppendIPv6Address(IPAddressFormatter<IPv6Address> formatter, IPv6Address address, String expected) {
            return dynamicTest(address.toString(), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        private DynamicContainer testFormatSpecificAppendBytes(IPAddressFormatter<IPv6Address> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.append((byte[]) null, new StringWriter()))),
                    dynamicTest("null Appender", () -> assertThrows(NullPointerException.class, () -> formatter.append(new byte[16], null))),
                    testFormatSpecificAppendBytes(formatter, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificAppendBytes(formatter, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificAppendBytes(formatter, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificAppendBytes(formatter, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificAppendBytes(formatter, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificAppendBytes(formatter, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificAppendBytes(formatter, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 0),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 4),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 15),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 17),
            };
            return dynamicContainer("append(byte[])", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAppendBytes(IPAddressFormatter<IPv6Address> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        private DynamicTest testFormatSpecificAppendBytesOfInvalidLength(IPAddressFormatter<IPv6Address> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.append(new byte[length], new StringWriter()));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAsFormat(IPAddressFormatter<IPv6Address> formatter, String expectedToStringPostfix,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            IPAddressFormat<IPv6Address> format = formatter.asFormat();
            DynamicNode[] nodes = {
                    testFormatSpecificAsFormatFormat(format, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAsFormatEquals(format),
                    testFormatSpecificAsFormatToString(format, expectedToStringPostfix),
                    testFormatSpecificAsFormatClone(format),
                    testFormatSpecificAsFormatSerialization(format),
            };
            return dynamicContainer("asFormat", Arrays.asList(nodes));
        }

        private DynamicContainer testFormatSpecificAsFormatFormat(IPAddressFormat<IPv6Address> format,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    testFormatSpecificAsFormatFormat(format, testAddress1, expectedFormatted1),
                    testFormatSpecificAsFormatFormat(format, testAddress2, expectedFormatted2),
                    testFormatSpecificAsFormatFormat(format, testAddress3, expectedFormatted3),
                    testFormatSpecificAsFormatFormat(format, testAddress4, expectedFormatted4),
                    testFormatSpecificAsFormatFormat(format, testAddress5, expectedFormatted5),
                    testFormatSpecificAsFormatFormat(format, testAddress6, expectedFormatted6),
                    testFormatSpecificAsFormatFormat(format, testAddress7, expectedFormatted7),

                    testFormatSpecificAsFormatFormat(format, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificAsFormatFormat(format, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificAsFormatFormat(format, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificAsFormatFormat(format, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificAsFormatFormat(format, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificAsFormatFormat(format, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificAsFormatFormat(format, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 0),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 4),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 15),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 17),

                    testFormatSpecificAsFormatFormatUnsupportedObject(format, null),
                    testFormatSpecificAsFormatFormatUnsupportedObject(format, IPv4Address.LOCALHOST),
                    testFormatSpecificAsFormatFormatUnsupportedObject(format, "string"),
            };
            return dynamicContainer("format", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAsFormatFormat(IPAddressFormat<IPv6Address> format, Object object, String expected) {
            return dynamicTest(object.toString(), () -> assertEquals(expected, format.format(object)));
        }

        private DynamicTest testFormatSpecificAsFormatFormat(IPAddressFormat<IPv6Address> format, byte[] array, String expected) {
            return dynamicTest(Arrays.toString(array), () -> assertEquals(expected, format.format(array)));
        }

        private DynamicTest testFormatSpecificAsFormatFormatBytesOfInvalidLength(IPAddressFormat<IPv6Address> format, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> format.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicTest testFormatSpecificAsFormatFormatUnsupportedObject(IPAddressFormat<IPv6Address> format, Object object) {
            return dynamicTest(String.format("unsupported: %s", object), () -> {
                IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> format.format(object));
                assertEquals(Messages.IPAddressFormat.unformattableObject(object), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAsFormatEquals(IPAddressFormat<IPv6Address> format) {
            IPAddressFormat<IPv6Address> other1 = IPAddressFormatter.ipv6()
                    .withShortStyle()
                    .build()
                    .asFormat();
            IPAddressFormat<IPv6Address> other2 = IPAddressFormatter.ipv6()
                    .withLongStyle()
                    .build()
                    .asFormat();
            IPAddressFormat<IPv6Address> other = format == other1 ? other2 : other1;

            DynamicTest[] tests = {
                    testFormatSpecificAsFormatEquals(format, format, true),
                    testFormatSpecificAsFormatEquals(format, null, false),
                    testFormatSpecificAsFormatEquals(format, IPAddressFormatter.ipv4().asFormat(), false),
                    testFormatSpecificAsFormatEquals(format, other, false),
            };
            return dynamicContainer("equals", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAsFormatEquals(IPAddressFormat<IPv6Address> format, Object object, boolean expectEquals) {
            BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
            return dynamicTest(String.valueOf(object), () -> equalsCheck.accept(format, object));
        }

        private DynamicTest testFormatSpecificAsFormatToString(IPAddressFormat<IPv6Address> format, String expectedToStringPostfix) {
            return dynamicTest("toString", () -> assertEquals(IPAddressFormat.class.getName() + expectedToStringPostfix, format.toString()));
        }

        @SuppressWarnings({ "deprecation", "unchecked" })
        private DynamicTest testFormatSpecificAsFormatClone(IPAddressFormat<IPv6Address> format) {
            return dynamicTest("clone", () -> {
                IPAddressFormat<IPv6Address> clone = (IPAddressFormat<IPv6Address>) format.clone();
                assertNotSame(format, clone);
                assertEquals(format.formatter(), clone.formatter());
                assertEquals(format, clone);
                assertEquals(format.hashCode(), clone.hashCode());
            });
        }

        private DynamicTest testFormatSpecificAsFormatSerialization(IPAddressFormat<IPv6Address> format) {
            return dynamicTest("serialization", () -> {
                IPAddressFormat<IPv6Address> copy = assertSerializable(format);
                assertSame(format, copy);
            });
        }

        private DynamicTest testFormatSpecificToString(IPAddressFormatter<IPv6Address> formatter, String expectedToStringPostfix) {
            return dynamicTest("toString", () -> assertEquals(IPAddressFormatter.class.getName() + expectedToStringPostfix, formatter.toString()));
        }

        @Nested
        @DisplayName("format agnostic")
        class FormatAgnostic {

            // valueOf is tested through IPv6AddressTest.testValueOfCharSequence

            @TestFactory
            @DisplayName("parse(CharSequence) and parse(CharSequence, int, int)")
            DynamicTest[] testParse() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertThrows(NullPointerException.class, () -> formatter.parse(null));
                            assertThrows(NullPointerException.class, () -> formatter.parse(null, 0, 0));
                        }),
                        testParseInvalid(formatter, "", 0),

                        testParse(formatter, "::1", IPv6Address.LOCALHOST),
                        testParse(formatter, "::", IPv6Address.MIN_VALUE),
                        testParse(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testParse(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testParse(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testParse(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testParse(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testParse(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testParse(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testParse(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testParse(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testParse(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testParse(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testParse(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testParseInvalid(formatter, "z::", 0),
                        testParseInvalid(formatter, "[::", 3),
                        testParseInvalid(formatter, "[::;", 3),
                        testParseInvalid(formatter, "12:::", 4),
                        testParseInvalid(formatter, "0:0:0:0:", 8),
                        testParseInvalid(formatter, "0:0:0:0:0:", 10),
                        testParseInvalid(formatter, "0:0:0:0:0:0:0", 13),
                        testParseInvalid(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseInvalid(formatter, "::192.", 6),
                };
            }

            private DynamicTest testParse(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected) {
                return dynamicTest(source, () -> {
                    assertEquals(expected, formatter.parse(source));
                    assertEquals(expected, formatter.parse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.parse("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
                });
            }

            private DynamicTest testParseInvalid(IPAddressFormatter<IPv6Address> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> formatter.parse(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                    assertEquals(Messages.IPv6Address.parseError(source), exception.getMessage());

                    exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(errorIndex + 1, exception.getErrorOffset());

                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parse(CharSequence, ParsePosition)")
            DynamicTest[] testParseWithPosition() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null))),
                        testParseInvalidWithPosition(formatter, "", 0),

                        testParseWithPosition(formatter, "::1", IPv6Address.LOCALHOST),
                        testParseWithPosition(formatter, "::", IPv6Address.MIN_VALUE),
                        testParseWithPosition(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab:cd:ef",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testParseWithPosition(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78:90::192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78::ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56::90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34::78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12::56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testParseInvalidWithPosition(formatter, "z::", 0),
                        testParseInvalidWithPosition(formatter, "[::", 3),
                        testParseInvalidWithPosition(formatter, "[::;", 3),
                        testParseWithPosition(formatter, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0), 4),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:", 8),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:", 10),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:0:0", 13),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseWithPosition(formatter, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192), 5),
                };
            }

            private DynamicTest testParseWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected) {
                return testParseWithPosition(formatter, source, expected, source.length());
            }

            private DynamicTest testParseWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected,
                    int expectedIndex) {

                return dynamicTest(source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    IPv6Address address = formatter.parse(source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String postfix = "z2345";
                    position.setIndex(0);
                    position.setErrorIndex(-1);
                    address = formatter.parse(source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parse(prefix + source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());

                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parse(prefix + source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());
                });
            }

            private DynamicTest testParseInvalidWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    assertNull(formatter.parse(source, position));
                    assertEquals(errorIndex, position.getErrorIndex());
                    assertEquals(0, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    assertNull(formatter.parse(prefix + source, position));
                    assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                    assertEquals(prefix.length(), position.getIndex());
                });
            }

            @TestFactory
            @DisplayName("tryParse")
            DynamicTest[] testTryParse() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertEquals(Optional.empty(), formatter.tryParse(null));
                            assertEquals(Optional.empty(), formatter.tryParse(null, 0, 0));
                        }),
                        testTryParse(formatter, "", Optional.empty()),

                        testTryParse(formatter, "::1", Optional.of(IPv6Address.LOCALHOST)),
                        testTryParse(formatter, "::", Optional.of(IPv6Address.MIN_VALUE)),
                        testTryParse(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Optional.of(IPv6Address.MAX_VALUE)),

                        testTryParse(formatter, "12:34:56:78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56:78:90:ab:cd::",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0))),
                        testTryParse(formatter, "12:34:56:78:90:ab::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0))),
                        testTryParse(formatter, "12:34:56:78:90::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0))),
                        testTryParse(formatter, "12:34:56:78::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0))),
                        testTryParse(formatter, "12:34:56::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0))),
                        testTryParse(formatter, "12:34::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0))),
                        testTryParse(formatter, "12::", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0))),

                        testTryParse(formatter, "12:34:56:78:90:ab::ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56:78:90::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56:78::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12::ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "::ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF))),

                        testTryParse(formatter, "12:34:56:78:90::cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56:78::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "::cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56:78:90::192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56:78::192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56:78::ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56:78::ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56::ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56::90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56::90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34::78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34::78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12::56:78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12::56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "[::]", Optional.of(IPv6Address.MIN_VALUE)),

                        testTryParse(formatter, "z::", Optional.empty()),
                        testTryParse(formatter, "[::", Optional.empty()),
                        testTryParse(formatter, "[::;", Optional.empty()),
                        testTryParse(formatter, "12:::", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:0:0", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:0:0;", Optional.empty()),
                        testTryParse(formatter, "::192.", Optional.empty()),
                };
            }

            private DynamicTest testTryParse(IPAddressFormatter<IPv6Address> formatter, String source, Optional<IPv6Address> expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(expected, formatter.tryParse(source));
                    assertEquals(expected, formatter.tryParse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.tryParse("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parseToBytes(CharSequence) and parseToBytes(CharSequence, int, int)")
            DynamicTest[] testParseToBytes() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null));
                            assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null, 0, 0));
                        }),
                        testParseToBytesInvalid(formatter, "", 0),

                        testParseToBytes(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testParseToBytes(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testParseToBytes(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesInvalid(formatter, "z::", 0),
                        testParseToBytesInvalid(formatter, "[::", 3),
                        testParseToBytesInvalid(formatter, "[::;", 3),
                        testParseToBytesInvalid(formatter, "12:::", 4),
                        testParseToBytesInvalid(formatter, "0:0:0:0:", 8),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:", 10),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:0:0", 13),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseToBytesInvalid(formatter, "::192.", 6),
                };
            }

            private DynamicTest testParseToBytes(IPAddressFormatter<IPv6Address> formatter, String source, byte[] expected) {
                return dynamicTest(source, () -> {
                    assertArrayEquals(expected, formatter.parseToBytes(source));
                    assertArrayEquals(expected, formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertArrayEquals(expected, formatter.parseToBytes("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, -1));
                });
            }

            private DynamicTest testParseToBytesInvalid(IPAddressFormatter<IPv6Address> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> formatter.parseToBytes(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                    assertEquals(Messages.IPv6Address.parseError(source), exception.getMessage());

                    exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(errorIndex + 1, exception.getErrorOffset());

                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parseToBytes(CharSequence, ParsePosition)")
            DynamicTest[] testParseToBytesWithPosition() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null, new ParsePosition(0)))),
                        dynamicTest("null position", () -> assertThrows(NullPointerException.class, () -> formatter.parseToBytes("127.0.0.1", null))),
                        testParseToBytesInvalidWithPosition(formatter, "", 0),

                        testParseToBytesWithPosition(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testParseToBytesWithPosition(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testParseToBytesWithPosition(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesInvalidWithPosition(formatter, "z::", 0),
                        testParseToBytesInvalidWithPosition(formatter, "[::", 3),
                        testParseToBytesInvalidWithPosition(formatter, "[::;", 3),
                        testParseToBytesWithPosition(formatter, "12:::", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }, 4),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:", 8),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:", 10),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:0:0", 13),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseToBytesWithPosition(formatter, "::192.", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 146,
                        }, 5),
                };
            }

            private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, byte[] expected) {
                return testParseToBytesWithPosition(formatter, source, expected, source.length());
            }

            private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPv6Address> formatter, String source,
                    byte[] expected, int expectedIndex) {

                return dynamicTest(source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    byte[] address = formatter.parseToBytes(source, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String postfix = "z2345";
                    position.setIndex(0);
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(source + postfix, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(prefix + source + postfix, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());

                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(prefix + source, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());
                });
            }

            private DynamicTest testParseToBytesInvalidWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    assertNull(formatter.parseToBytes(source, position));
                    assertEquals(errorIndex, position.getErrorIndex());
                    assertEquals(0, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    assertNull(formatter.parseToBytes(prefix + source, position));
                    assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                    assertEquals(prefix.length(), position.getIndex());
                });
            }

            @TestFactory
            @DisplayName("tryParseToBytes")
            DynamicTest[] testTryParseToBytes() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertEquals(Optional.empty(), formatter.tryParseToBytes(null));
                            assertEquals(Optional.empty(), formatter.tryParseToBytes(null, 0, 0));
                        }),
                        testTryParseToBytesEmptyOptional(formatter, ""),

                        testTryParseToBytes(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testTryParseToBytes(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testTryParseToBytes(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testTryParseToBytesEmptyOptional(formatter, "z::"),
                        testTryParseToBytesEmptyOptional(formatter, "[::"),
                        testTryParseToBytesEmptyOptional(formatter, "[::;"),
                        testTryParseToBytesEmptyOptional(formatter, "12:::"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:0:0"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:0:0;"),
                        testTryParseToBytesEmptyOptional(formatter, "::192."),
                };
            }

            private DynamicTest testTryParseToBytes(IPAddressFormatter<IPv6Address> formatter, String source, byte[] expected) {
                return dynamicTest(source, () -> {
                    assertArrayEquals(expected, formatter.tryParseToBytes(source).get());
                    assertArrayEquals(expected, formatter.tryParseToBytes("1" + source + "1", 1, 1 + source.length()).get());
                    assertArrayEquals(expected, formatter.tryParseToBytes("z" + source + "z", 1, 1 + source.length()).get());
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
                });
            }

            private DynamicTest testTryParseToBytesEmptyOptional(IPAddressFormatter<IPv6Address> formatter, String source) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(Optional.empty(), formatter.tryParseToBytes(source));
                    assertEquals(Optional.empty(), formatter.tryParseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(Optional.empty(), formatter.tryParseToBytes("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
                });
            }

            @Nested
            @DisplayName("asFormat")
            class AsFormat {

                @TestFactory
                @DisplayName("parseObject(String)")
                DynamicTest[] testParseObject() {
                    IPAddressFormat<IPv6Address> format = IPAddressFormatter.ipv6WithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null))),
                            testParseObjectInvalid(format, "", 0),

                            testParseObject(format, "::1", IPv6Address.LOCALHOST),
                            testParseObject(format, "::", IPv6Address.MIN_VALUE),
                            testParseObject(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParseObject(format, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParseObject(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParseObject(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParseObject(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParseObject(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParseObject(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParseObject(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParseObject(format, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParseObject(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParseObject(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParseObject(format, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "[::]", IPv6Address.MIN_VALUE),
                            // parsing stops after :: for the next two
                            testParseObject(format, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),
                            testParseObject(format, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192)),

                            testParseObjectInvalid(format, "z::", 0),
                            testParseObjectInvalid(format, "[::", 3),
                            testParseObjectInvalid(format, "[::;", 3),
                            testParseObjectInvalid(format, "0:0:0:0:", 8),
                            testParseObjectInvalid(format, "0:0:0:0:0:", 10),
                            testParseObjectInvalid(format, "0:0:0:0:0:0:0", 13),
                            testParseObjectInvalid(format, "0:0:0:0:0:0:0;", 13),
                    };
                }

                private DynamicTest testParseObject(IPAddressFormat<IPv6Address> format, String source, IPv6Address expected) {
                    return dynamicTest(source, () -> assertEquals(expected, format.parseObject(source)));
                }

                private DynamicTest testParseObjectInvalid(IPAddressFormat<IPv6Address> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParseException exception = assertThrows(ParseException.class, () -> format.parseObject(source));
                        assertEquals(errorIndex, exception.getErrorOffset());
                    });
                }

                @TestFactory
                @DisplayName("parseObject(String, ParsePosition)")
                DynamicTest[] testParseObjectWithPosition() {
                    IPAddressFormat<IPv6Address> format = IPAddressFormatter.ipv6WithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null))),
                            testParseObjectInvalidWithPosition(format, "", 0),

                            testParseObjectWithPosition(format, "::1", IPv6Address.LOCALHOST),
                            testParseObjectWithPosition(format, "::", IPv6Address.MIN_VALUE),
                            testParseObjectWithPosition(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:cd::",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab::ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78:90::cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78:90::192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56:78::192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56:78::ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78::ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56::ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56::90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56::90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34::78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12::56:78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12::56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "[::]", IPv6Address.MIN_VALUE),

                            testParseObjectInvalidWithPosition(format, "z::", 0),
                            testParseObjectInvalidWithPosition(format, "[::", 3),
                            testParseObjectInvalidWithPosition(format, "[::;", 3),
                            testParseObjectWithPosition(format, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0), 4),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:", 8),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:", 10),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:0:0", 13),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:0:0;", 13),
                            testParseObjectWithPosition(format, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192), 5),
                    };
                }

                private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPv6Address> format, String source, IPv6Address expected) {
                    return testParseObjectWithPosition(format, source, expected, source.length());
                }

                private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPv6Address> format, String source, IPv6Address expected,
                        int expectedIndex) {

                    return dynamicTest(source, () -> {
                        ParsePosition position = new ParsePosition(0);
                        IPv6Address address = format.parseObject(source, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(expectedIndex, position.getIndex());

                        String postfix = "z2345";
                        position.setIndex(0);
                        position.setErrorIndex(-1);
                        address = format.parseObject(source + postfix, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(expectedIndex, position.getIndex());

                        String prefix = "12345";
                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        address = format.parseObject(prefix + source + postfix, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(prefix.length() + expectedIndex, position.getIndex());

                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        address = format.parseObject(prefix + source, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(prefix.length() + expectedIndex, position.getIndex());
                    });
                }

                private DynamicTest testParseObjectInvalidWithPosition(IPAddressFormat<IPv6Address> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParsePosition position = new ParsePosition(0);
                        assertNull(format.parseObject(source, position));
                        assertEquals(errorIndex, position.getErrorIndex());
                        assertEquals(0, position.getIndex());

                        String prefix = "12345";
                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        assertNull(format.parseObject(prefix + source, position));
                        assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                        assertEquals(prefix.length(), position.getIndex());
                    });
                }

                // parse(CharSequence source, ParsePosition position) is tested through parseObject

                @TestFactory
                @DisplayName("parse(CharSequence)")
                DynamicTest[] testParse() {
                    IPAddressFormat<IPv6Address> format = IPAddressFormatter.ipv6WithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parse(null))),
                            testParseInvalid(format, "", 0),

                            testParse(format, "::1", IPv6Address.LOCALHOST),
                            testParse(format, "::", IPv6Address.MIN_VALUE),
                            testParse(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParse(format, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParse(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParse(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParse(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParse(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParse(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParse(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParse(format, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParse(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParse(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParse(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParse(format, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParse(format, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "[::]", IPv6Address.MIN_VALUE),

                            testParseInvalid(format, "z::", 0),
                            testParseInvalid(format, "[::", 3),
                            testParseInvalid(format, "[::;", 3),
                            testParseInvalid(format, "12:::", 4),
                            testParseInvalid(format, "0:0:0:0:", 8),
                            testParseInvalid(format, "0:0:0:0:0:", 10),
                            testParseInvalid(format, "0:0:0:0:0:0:0", 13),
                            testParseInvalid(format, "0:0:0:0:0:0:0;", 13),
                            testParseInvalid(format, "::192.", 6),
                    };
                }

                private DynamicTest testParse(IPAddressFormat<IPv6Address> format, String source, IPv6Address expected) {
                    return dynamicTest(source, () -> assertEquals(expected, format.parse(source)));
                }

                private DynamicTest testParseInvalid(IPAddressFormat<IPv6Address> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParseException exception = assertThrows(ParseException.class, () -> format.parse(source));
                        assertEquals(errorIndex, exception.getErrorOffset());
                    });
                }
            }

            @TestFactory
            @DisplayName("isValid")
            DynamicTest[] testIsValid() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertEquals(false, formatter.isValid(null, 0, 0))),
                        testIsValid(formatter, "", false),

                        testIsValid(formatter, "::1", true),
                        testIsValid(formatter, "::", true),
                        testIsValid(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),

                        testIsValid(formatter, "12:34:56:78:90:ab:cd:ef", true),
                        testIsValid(formatter, "12:34:56:78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34:56:78:90:ab:cd::", true),
                        testIsValid(formatter, "12:34:56:78:90:ab::", true),
                        testIsValid(formatter, "12:34:56:78:90::", true),
                        testIsValid(formatter, "12:34:56:78::", true),
                        testIsValid(formatter, "12:34:56::", true),
                        testIsValid(formatter, "12:34::", true),
                        testIsValid(formatter, "12::", true),

                        testIsValid(formatter, "12:34:56:78:90:ab::ef", true),
                        testIsValid(formatter, "12:34:56:78:90::ef", true),
                        testIsValid(formatter, "12:34:56:78::ef", true),
                        testIsValid(formatter, "12:34:56::ef", true),
                        testIsValid(formatter, "12:34::ef", true),
                        testIsValid(formatter, "12::ef", true),
                        testIsValid(formatter, "::ef", true),

                        testIsValid(formatter, "12:34:56:78:90::cd:ef", true),
                        testIsValid(formatter, "12:34:56:78::cd:ef", true),
                        testIsValid(formatter, "12:34:56::cd:ef", true),
                        testIsValid(formatter, "12:34::cd:ef", true),
                        testIsValid(formatter, "12::cd:ef", true),
                        testIsValid(formatter, "::cd:ef", true),

                        testIsValid(formatter, "12:34:56:78:90::192.168.0.1", true),
                        testIsValid(formatter, "12:34:56:78::192.168.0.1", true),
                        testIsValid(formatter, "12:34:56::192.168.0.1", true),
                        testIsValid(formatter, "12:34::192.168.0.1", true),
                        testIsValid(formatter, "12::192.168.0.1", true),
                        testIsValid(formatter, "::192.168.0.1", true),

                        testIsValid(formatter, "12:34:56:78::ab:cd:ef", true),
                        testIsValid(formatter, "12:34:56::ab:cd:ef", true),
                        testIsValid(formatter, "12:34::ab:cd:ef", true),
                        testIsValid(formatter, "12::ab:cd:ef", true),
                        testIsValid(formatter, "::ab:cd:ef", true),

                        testIsValid(formatter, "12:34:56:78::ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34:56::ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34::ab:192.168.0.1", true),
                        testIsValid(formatter, "12::ab:192.168.0.1", true),
                        testIsValid(formatter, "::ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34:56::90:ab:cd:ef", true),
                        testIsValid(formatter, "12:34::90:ab:cd:ef", true),
                        testIsValid(formatter, "12::90:ab:cd:ef", true),
                        testIsValid(formatter, "::90:ab:cd:ef", true),

                        testIsValid(formatter, "12:34:56::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34::78:90:ab:cd:ef", true),
                        testIsValid(formatter, "12::78:90:ab:cd:ef", true),
                        testIsValid(formatter, "::78:90:ab:cd:ef", true),

                        testIsValid(formatter, "12:34::78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12::78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12::56:78:90:ab:cd:ef", true),
                        testIsValid(formatter, "::56:78:90:ab:cd:ef", true),

                        testIsValid(formatter, "12::56:78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::56:78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "[::]", true),

                        testIsValid(formatter, "z::", false),
                        testIsValid(formatter, "[::", false),
                        testIsValid(formatter, "[::;", false),
                        testIsValid(formatter, "12:::", false),
                        testIsValid(formatter, "0:0:0:0:", false),
                        testIsValid(formatter, "0:0:0:0:0:", false),
                        testIsValid(formatter, "0:0:0:0:0:0:0", false),
                        testIsValid(formatter, "0:0:0:0:0:0:0;", false),
                        testIsValid(formatter, "::192.", false),
                };
            }

            private DynamicTest testIsValid(IPAddressFormatter<IPv6Address> formatter, String source, boolean expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(expected, formatter.isValid(source, 0, source.length()));
                    assertEquals(expected, formatter.isValid("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.isValid("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("testIfValid")
            DynamicTest[] testTestIfValid() {
                IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
                return new DynamicTest[] {
                        testTestIfValid(formatter, null, null),
                        testTestIfValid(formatter, "", null),

                        testTestIfValid(formatter, "::1", IPv6Address.LOCALHOST),
                        testTestIfValid(formatter, "::", IPv6Address.MIN_VALUE),
                        testTestIfValid(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testTestIfValid(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testTestIfValid(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testTestIfValid(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testTestIfValid(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testTestIfValid(formatter, "z::", null),
                        testTestIfValid(formatter, "[::", null),
                        testTestIfValid(formatter, "[::;", null),
                        testTestIfValid(formatter, "12:::", null),
                        testTestIfValid(formatter, "0:0:0:0:", null),
                        testTestIfValid(formatter, "0:0:0:0:0:", null),
                        testTestIfValid(formatter, "0:0:0:0:0:0:0", null),
                        testTestIfValid(formatter, "0:0:0:0:0:0:0;", null),
                        testTestIfValid(formatter, "::192.", null),
                };
            }

            private DynamicTest testTestIfValid(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    testTestIfValid(formatter, source, expected, true);
                    testTestIfValid(formatter, source, expected, false);
                });
            }

            @SuppressWarnings("unchecked")
            private void testTestIfValid(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected, boolean testResult) {
                Predicate<? super IPv6Address> predicate = mock(Predicate.class);
                when(predicate.test(any())).thenReturn(testResult);

                boolean result = formatter.testIfValid(source, predicate);
                if (expected != null) {
                    assertEquals(testResult, result);
                    verify(predicate).test(expected);
                } else {
                    assertEquals(false, result);
                }
                verifyNoMoreInteractions(predicate);
            }
        }
    }

    @Nested
    class AnyVersion {

        private final IPv6Address testAddress1 = IPv6Address.valueOf(0L, 0L);
        private final IPv6Address testAddress2 = IPv6Address.valueOf(0L, 1L);
        private final IPv6Address testAddress3 = IPv6Address.valueOf(0x0001000000000000L, 0L);
        // no zeroes sections
        private final IPv6Address testAddress4 = IPv6Address.valueOf(0x0123045607890100L, 0xABCDEF0010000001L);
        // one zeroes sections
        private final IPv6Address testAddress5 = IPv6Address.valueOf(0x1200000000000000L, 0x0000123400010001L);
        // two zeroes sections, the first one being the longest
        private final IPv6Address testAddress6 = IPv6Address.valueOf(0x1200000000000000L, 0x0000123400000000L);
        // two zeroes sections, the second one being the longest
        private final IPv6Address testAddress7 = IPv6Address.valueOf(0x1200000000001234L, 0x5678000000000000L);

        @TestFactory
        @DisplayName("format specific")
        DynamicContainer[] testFormatSpecific() {
            return new DynamicContainer[] {
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "::", "::1", "1::", "123:456:789:100:abcd:ef00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:abcd:ef00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "::", "::1", "1::", "123:456:789:100:ABCD:EF00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:ABCD:EF00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:abcd:ef00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:abcd:ef00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:ABCD:EF00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:ABCD:EF00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:abcd:ef00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:abcd:ef00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:abcd:ef00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:abcd:ef00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:ABCD:EF00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:ABCD:EF00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=false]",
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:ABCD:EF00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0"),
                    testFormatSpecific(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=true]",
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:ABCD:EF00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]"),
            };
        }

        private DynamicContainer testFormatSpecific(Builder<IPAddress<?>> builder, String expectedToStringPostfix,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            IPAddressFormatter<IPAddress<?>> formatter = builder.build();
            String displayName = formatter.toString().replaceAll(".*\\[(.*)\\]", "$1");

            DynamicNode[] nodes = {
                    testFormatSpecificFormatIPAddress(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificFormatBytes(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAppendIPAddress(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAppendBytes(formatter, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAsFormat(formatter, expectedToStringPostfix, expectedFormatted1, expectedFormatted2, expectedFormatted3,
                            expectedFormatted4, expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificToString(formatter, expectedToStringPostfix),
            };
            return dynamicContainer(displayName, Arrays.asList(nodes));
        }

        private DynamicContainer testFormatSpecificFormatIPAddress(IPAddressFormatter<IPAddress<?>> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.format((IPAddress<?>) null));
                        assertThrows(NullPointerException.class, () -> formatter.format((IPAddress<?>) null, new StringBuilder()));
                        assertThrows(NullPointerException.class, () -> formatter.format((IPAddress<?>) null, new StringBuffer()));
                    }),
                    dynamicTest("null StringBuilder",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(IPv6Address.LOCALHOST, (StringBuilder) null))),
                    dynamicTest("null StringBuffer",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(IPv6Address.LOCALHOST, (StringBuilder) null))),

                    dynamicTest("unsupported IP address", () -> {
                        IllegalStateException exception;
                        exception = assertThrows(IllegalStateException.class, () -> formatter.format(new TestIPAddress()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                        exception = assertThrows(IllegalStateException.class, () -> formatter.format(new TestIPAddress(), new StringBuilder()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                        exception = assertThrows(IllegalStateException.class, () -> formatter.format(new TestIPAddress(), new StringBuffer()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                    }),

                    testFormatSpecificFormatIPAddress(formatter, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testFormatSpecificFormatIPAddress(formatter, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testFormatSpecificFormatIPAddress(formatter, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testFormatSpecificFormatIPAddress(formatter, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testFormatSpecificFormatIPAddress(formatter, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),

                    testFormatSpecificFormatIPAddress(formatter, testAddress1, expectedFormatted1),
                    testFormatSpecificFormatIPAddress(formatter, testAddress2, expectedFormatted2),
                    testFormatSpecificFormatIPAddress(formatter, testAddress3, expectedFormatted3),
                    testFormatSpecificFormatIPAddress(formatter, testAddress4, expectedFormatted4),
                    testFormatSpecificFormatIPAddress(formatter, testAddress5, expectedFormatted5),
                    testFormatSpecificFormatIPAddress(formatter, testAddress6, expectedFormatted6),
                    testFormatSpecificFormatIPAddress(formatter, testAddress7, expectedFormatted7),
            };
            return dynamicContainer("format(IPAddress)", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificFormatIPAddress(IPAddressFormatter<IPAddress<?>> formatter, IPAddress<?> address, String expected) {
            return dynamicTest(address.toString(), () -> {
                assertEquals(expected, formatter.format(address));
                assertEquals(expected, formatter.format(address, new StringBuilder()).toString());
                assertEquals(expected, formatter.format(address, new StringBuffer()).toString());
            });
        }

        private DynamicContainer testFormatSpecificFormatBytes(IPAddressFormatter<IPAddress<?>> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> {
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null));
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null, new StringBuilder()));
                        assertThrows(NullPointerException.class, () -> formatter.format((byte[]) null, new StringBuffer()));
                    }),
                    dynamicTest("null StringBuilder",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(new byte[16], (StringBuilder) null))),
                    dynamicTest("null StringBuffer",
                            () -> assertThrows(NullPointerException.class, () -> formatter.format(new byte[16], (StringBuilder) null))),

                    testFormatSpecificFormatBytes(formatter, IPv4Address.LOCALHOST.toByteArray(), "127.0.0.1"),
                    testFormatSpecificFormatBytes(formatter, IPv4Address.MIN_VALUE.toByteArray(), "0.0.0.0"),
                    testFormatSpecificFormatBytes(formatter, IPv4Address.MAX_VALUE.toByteArray(), "255.255.255.255"),
                    testFormatSpecificFormatBytes(formatter, IPv4Address.valueOf(123, 234, 210, 109).toByteArray(), "123.234.210.109"),
                    testFormatSpecificFormatBytes(formatter, IPv4Address.valueOf(1, 2, 3, 4).toByteArray(), "1.2.3.4"),

                    testFormatSpecificFormatBytes(formatter, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificFormatBytes(formatter, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificFormatBytes(formatter, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificFormatBytes(formatter, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificFormatBytes(formatter, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificFormatBytes(formatter, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificFormatBytes(formatter, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 0),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 3),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 5),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 15),
                    testFormatSpecificFormatBytesOfInvalidLength(formatter, 17),
            };
            return dynamicContainer("format(byte[])", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificFormatBytes(IPAddressFormatter<IPAddress<?>> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> {
                assertEquals(expected, formatter.format(address));
                assertEquals(expected, formatter.format(address, new StringBuilder()).toString());
                assertEquals(expected, formatter.format(address, new StringBuffer()).toString());
            });
        }

        private DynamicTest testFormatSpecificFormatBytesOfInvalidLength(IPAddressFormatter<IPAddress<?>> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length], new StringBuilder()));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAppendIPAddress(IPAddressFormatter<IPAddress<?>> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null",
                            () -> assertThrows(NullPointerException.class, () -> formatter.append((IPAddress<?>) null, new StringWriter()))),
                    dynamicTest("null Appender", () -> assertThrows(NullPointerException.class, () -> formatter.append(IPv6Address.LOCALHOST, null))),

                    dynamicTest("unsupported IP address", () -> {
                        IllegalStateException exception;
                        exception = assertThrows(IllegalStateException.class, () -> formatter.append(new TestIPAddress(), new StringWriter()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                    }),

                    testFormatSpecificAppendIPAddress(formatter, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testFormatSpecificAppendIPAddress(formatter, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testFormatSpecificAppendIPAddress(formatter, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testFormatSpecificAppendIPAddress(formatter, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testFormatSpecificAppendIPAddress(formatter, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),

                    testFormatSpecificAppendIPAddress(formatter, testAddress1, expectedFormatted1),
                    testFormatSpecificAppendIPAddress(formatter, testAddress2, expectedFormatted2),
                    testFormatSpecificAppendIPAddress(formatter, testAddress3, expectedFormatted3),
                    testFormatSpecificAppendIPAddress(formatter, testAddress4, expectedFormatted4),
                    testFormatSpecificAppendIPAddress(formatter, testAddress5, expectedFormatted5),
                    testFormatSpecificAppendIPAddress(formatter, testAddress6, expectedFormatted6),
                    testFormatSpecificAppendIPAddress(formatter, testAddress7, expectedFormatted7),
            };
            return dynamicContainer("append(IPAddress)", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAppendIPAddress(IPAddressFormatter<IPAddress<?>> formatter, IPAddress<?> address, String expected) {
            return dynamicTest(address.toString(), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        private DynamicContainer testFormatSpecificAppendBytes(IPAddressFormatter<IPAddress<?>> formatter,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.append((byte[]) null, new StringWriter()))),
                    dynamicTest("null Appender", () -> assertThrows(NullPointerException.class, () -> formatter.append(new byte[16], null))),

                    testFormatSpecificAppendBytes(formatter, IPv4Address.LOCALHOST.toByteArray(), "127.0.0.1"),
                    testFormatSpecificAppendBytes(formatter, IPv4Address.MIN_VALUE.toByteArray(), "0.0.0.0"),
                    testFormatSpecificAppendBytes(formatter, IPv4Address.MAX_VALUE.toByteArray(), "255.255.255.255"),
                    testFormatSpecificAppendBytes(formatter, IPv4Address.valueOf(123, 234, 210, 109).toByteArray(), "123.234.210.109"),
                    testFormatSpecificAppendBytes(formatter, IPv4Address.valueOf(1, 2, 3, 4).toByteArray(), "1.2.3.4"),

                    testFormatSpecificAppendBytes(formatter, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificAppendBytes(formatter, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificAppendBytes(formatter, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificAppendBytes(formatter, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificAppendBytes(formatter, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificAppendBytes(formatter, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificAppendBytes(formatter, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 0),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 3),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 5),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 15),
                    testFormatSpecificAppendBytesOfInvalidLength(formatter, 17),
            };
            return dynamicContainer("append(byte[])", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAppendBytes(IPAddressFormatter<IPAddress<?>> formatter, byte[] address, String expected) {
            return dynamicTest(Arrays.toString(address), () -> {
                StringWriter dest = new StringWriter();
                assertSame(dest, formatter.append(address, dest));
                assertEquals(expected, dest.toString());
            });
        }

        private DynamicTest testFormatSpecificAppendBytesOfInvalidLength(IPAddressFormatter<IPAddress<?>> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.append(new byte[length], new StringWriter()));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAsFormat(IPAddressFormatter<IPAddress<?>> formatter, String expectedToStringPostfix,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            IPAddressFormat<?> format = formatter.asFormat();
            DynamicNode[] nodes = {
                    testFormatSpecificAsFormatFormat(format, expectedFormatted1, expectedFormatted2, expectedFormatted3, expectedFormatted4,
                            expectedFormatted5, expectedFormatted6, expectedFormatted7),
                    testFormatSpecificAsFormatEquals(format),
                    testFormatSpecificAsFormatToString(format, expectedToStringPostfix),
                    testFormatSpecificAsFormatClone(format),
                    testFormatSpecificAsFormatSerialization(format),
            };
            return dynamicContainer("asFormat", Arrays.asList(nodes));
        }

        private DynamicContainer testFormatSpecificAsFormatFormat(IPAddressFormat<?> format,
                String expectedFormatted1, String expectedFormatted2, String expectedFormatted3, String expectedFormatted4,
                String expectedFormatted5, String expectedFormatted6, String expectedFormatted7) {

            DynamicTest[] tests = {
                    testFormatSpecificAsFormatFormat(format, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),

                    testFormatSpecificAsFormatFormat(format, IPv4Address.LOCALHOST.toByteArray(), "127.0.0.1"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.MIN_VALUE.toByteArray(), "0.0.0.0"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.MAX_VALUE.toByteArray(), "255.255.255.255"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.valueOf(123, 234, 210, 109).toByteArray(), "123.234.210.109"),
                    testFormatSpecificAsFormatFormat(format, IPv4Address.valueOf(1, 2, 3, 4).toByteArray(), "1.2.3.4"),

                    testFormatSpecificAsFormatFormat(format, testAddress1, expectedFormatted1),
                    testFormatSpecificAsFormatFormat(format, testAddress2, expectedFormatted2),
                    testFormatSpecificAsFormatFormat(format, testAddress3, expectedFormatted3),
                    testFormatSpecificAsFormatFormat(format, testAddress4, expectedFormatted4),
                    testFormatSpecificAsFormatFormat(format, testAddress5, expectedFormatted5),
                    testFormatSpecificAsFormatFormat(format, testAddress6, expectedFormatted6),
                    testFormatSpecificAsFormatFormat(format, testAddress7, expectedFormatted7),

                    testFormatSpecificAsFormatFormat(format, testAddress1.toByteArray(), expectedFormatted1),
                    testFormatSpecificAsFormatFormat(format, testAddress2.toByteArray(), expectedFormatted2),
                    testFormatSpecificAsFormatFormat(format, testAddress3.toByteArray(), expectedFormatted3),
                    testFormatSpecificAsFormatFormat(format, testAddress4.toByteArray(), expectedFormatted4),
                    testFormatSpecificAsFormatFormat(format, testAddress5.toByteArray(), expectedFormatted5),
                    testFormatSpecificAsFormatFormat(format, testAddress6.toByteArray(), expectedFormatted6),
                    testFormatSpecificAsFormatFormat(format, testAddress7.toByteArray(), expectedFormatted7),

                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 0),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 3),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 5),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 15),
                    testFormatSpecificAsFormatFormatBytesOfInvalidLength(format, 17),

                    testFormatSpecificAsFormatFormatUnsupportedObject(format, null),
                    testFormatSpecificAsFormatFormatUnsupportedObject(format, "string"),
            };
            return dynamicContainer("format", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAsFormatFormat(IPAddressFormat<?> format, Object object, String expected) {
            return dynamicTest(object.toString(), () -> assertEquals(expected, format.format(object)));
        }

        private DynamicTest testFormatSpecificAsFormatFormat(IPAddressFormat<?> format, byte[] array, String expected) {
            return dynamicTest(Arrays.toString(array), () -> assertEquals(expected, format.format(array)));
        }

        private DynamicTest testFormatSpecificAsFormatFormatBytesOfInvalidLength(IPAddressFormat<?> format, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> format.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize(length), exception.getMessage());
            });
        }

        private DynamicTest testFormatSpecificAsFormatFormatUnsupportedObject(IPAddressFormat<?> format, Object object) {
            return dynamicTest(String.format("unsupported: %s", object), () -> {
                IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> format.format(object));
                assertEquals(Messages.IPAddressFormat.unformattableObject(object), exception.getMessage());
            });
        }

        private DynamicContainer testFormatSpecificAsFormatEquals(IPAddressFormat<?> format) {
            IPAddressFormat<IPAddress<?>> other1 = IPAddressFormatter.anyVersion()
                    .withShortStyle()
                    .build()
                    .asFormat();
            IPAddressFormat<IPAddress<?>> other2 = IPAddressFormatter.anyVersion()
                    .withLongStyle()
                    .build()
                    .asFormat();
            IPAddressFormat<IPAddress<?>> other = format == other1 ? other2 : other1;

            DynamicTest[] tests = {
                    testFormatSpecificAsFormatEquals(format, format, true),
                    testFormatSpecificAsFormatEquals(format, null, false),
                    testFormatSpecificAsFormatEquals(format, IPAddressFormatter.ipv4().asFormat(), false),
                    testFormatSpecificAsFormatEquals(format, other, false),
            };
            return dynamicContainer("equals", Arrays.asList(tests));
        }

        private DynamicTest testFormatSpecificAsFormatEquals(IPAddressFormat<?> format, Object object, boolean expectEquals) {
            BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
            return dynamicTest(String.valueOf(object), () -> equalsCheck.accept(format, object));
        }

        private DynamicTest testFormatSpecificAsFormatToString(IPAddressFormat<?> format, String expectedToStringPostfix) {
            return dynamicTest("toString", () -> assertEquals(IPAddressFormat.class.getName() + expectedToStringPostfix, format.toString()));
        }

        @SuppressWarnings("deprecation")
        private DynamicTest testFormatSpecificAsFormatClone(IPAddressFormat<?> format) {
            return dynamicTest("clone", () -> {
                IPAddressFormat<?> clone = (IPAddressFormat<?>) format.clone();
                assertNotSame(format, clone);
                assertEquals(format.formatter(), clone.formatter());
                assertEquals(format, clone);
                assertEquals(format.hashCode(), clone.hashCode());
            });
        }

        private DynamicTest testFormatSpecificAsFormatSerialization(IPAddressFormat<?> format) {
            return dynamicTest("serialization", () -> {
                IPAddressFormat<?> copy = assertSerializable(format);
                assertSame(format, copy);
            });
        }

        private DynamicTest testFormatSpecificToString(IPAddressFormatter<IPAddress<?>> formatter, String expectedToStringPostfix) {
            return dynamicTest("toString", () -> assertEquals(IPAddressFormatter.class.getName() + expectedToStringPostfix, formatter.toString()));
        }

        @Nested
        @DisplayName("format agnostic")
        class FormatAgnostic {

            // valueOf is tested through IPAddressTest.testValueOfCharSequence

            @TestFactory
            @DisplayName("parse(CharSequence) and parse(CharSequence, int, int)")
            DynamicTest[] testParse() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertThrows(NullPointerException.class, () -> formatter.parse(null));
                            assertThrows(NullPointerException.class, () -> formatter.parse(null, 0, 0));
                        }),
                        testParseInvalid(formatter, "", 0),

                        testParse(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                        testParse(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testParse(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testParse(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),

                        testParse(formatter, "::1", IPv6Address.LOCALHOST),
                        testParse(formatter, "::", IPv6Address.MIN_VALUE),
                        testParse(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testParse(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testParse(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testParse(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testParse(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testParse(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testParse(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testParse(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testParse(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testParse(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testParse(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testParse(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testParse(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParse(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParse(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParse(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParse(formatter, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParse(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParse(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testParseInvalid(formatter, ".34.56.78", 0),
                        testParseInvalid(formatter, "12..56.78", 3),
                        testParseInvalid(formatter, "12.34..78", 6),
                        testParseInvalid(formatter, "12.34.56.", 9),
                        testParseInvalid(formatter, "1234.456.789.0", 3),
                        testParseInvalid(formatter, "123.456.789.0", 6),
                        testParseInvalid(formatter, "12.34.56.789", 11),
                        testParseInvalid(formatter, "12.34.56", 8),

                        testParseInvalid(formatter, "z::", 0),
                        testParseInvalid(formatter, "[::", 3),
                        testParseInvalid(formatter, "[::;", 3),
                        testParseInvalid(formatter, "12:::", 4),
                        testParseInvalid(formatter, "0:0:0:0:", 8),
                        testParseInvalid(formatter, "0:0:0:0:0:", 10),
                        testParseInvalid(formatter, "0:0:0:0:0:0:0", 13),
                        testParseInvalid(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseInvalid(formatter, "::192.", 6),

                        testParseInvalid(formatter, "192.168.0.1:8080", 11),
                };
            }

            private DynamicTest testParse(IPAddressFormatter<IPAddress<?>> formatter, String source, IPAddress<?> expected) {
                return dynamicTest(source, () -> {
                    assertEquals(expected, formatter.parse(source));
                    assertEquals(expected, formatter.parse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.parse("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
                });
            }

            private DynamicTest testParseInvalid(IPAddressFormatter<IPAddress<?>> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> formatter.parse(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                    assertEquals(Messages.IPAddress.parseError(source), exception.getMessage());

                    exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(errorIndex + 1, exception.getErrorOffset());

                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parse(CharSequence, ParsePosition)")
            DynamicTest[] testParseWithPosition() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null))),
                        testParseInvalidWithPosition(formatter, "", 0),

                        testParseWithPosition(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                        testParseWithPosition(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testParseWithPosition(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testParseWithPosition(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),

                        testParseWithPosition(formatter, "::1", IPv6Address.LOCALHOST),
                        testParseWithPosition(formatter, "::", IPv6Address.MIN_VALUE),
                        testParseWithPosition(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab:cd:ef",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testParseWithPosition(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testParseWithPosition(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testParseWithPosition(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testParseWithPosition(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78:90::192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56:78::ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34:56::90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12:34::78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testParseWithPosition(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testParseWithPosition(formatter, "12::56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testParseWithPosition(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testParseWithPosition(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testParseInvalidWithPosition(formatter, ".34.56.78", 0),
                        testParseInvalidWithPosition(formatter, "12..56.78", 3),
                        testParseInvalidWithPosition(formatter, "12.34..78", 6),
                        testParseInvalidWithPosition(formatter, "12.34.56.", 9),
                        testParseInvalidWithPosition(formatter, "1234.456.789.0", 3),
                        testParseInvalidWithPosition(formatter, "123.456.789.0", 6),
                        testParseWithPosition(formatter, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78), 11),
                        testParseInvalidWithPosition(formatter, "12.34.56", 8),

                        testParseInvalidWithPosition(formatter, "z::", 0),
                        testParseInvalidWithPosition(formatter, "[::", 3),
                        testParseInvalidWithPosition(formatter, "[::;", 3),
                        testParseWithPosition(formatter, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0), 4),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:", 8),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:", 10),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:0:0", 13),
                        testParseInvalidWithPosition(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseWithPosition(formatter, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192), 5),

                        testParseWithPosition(formatter, "192.168.0.1:8080", IPv4Address.valueOf(192, 168, 0, 1), 11),
                };
            }

            private DynamicTest testParseWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source, IPAddress<?> expected) {
                return testParseWithPosition(formatter, source, expected, source.length());
            }

            private DynamicTest testParseWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source, IPAddress<?> expected,
                    int expectedIndex) {

                return dynamicTest(source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    IPAddress<?> address = formatter.parse(source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String postfix = "z2345";
                    position.setIndex(0);
                    position.setErrorIndex(-1);
                    address = formatter.parse(source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parse(prefix + source + postfix, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());

                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parse(prefix + source, position);
                    assertEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());
                });
            }

            private DynamicTest testParseInvalidWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    assertNull(formatter.parse(source, position));
                    assertEquals(errorIndex, position.getErrorIndex());
                    assertEquals(0, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    assertNull(formatter.parse(prefix + source, position));
                    assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                    assertEquals(prefix.length(), position.getIndex());
                });
            }

            @TestFactory
            @DisplayName("tryParse")
            DynamicTest[] testTryParse() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertEquals(Optional.empty(), formatter.tryParse(null));
                            assertEquals(Optional.empty(), formatter.tryParse(null, 0, 0));
                        }),
                        testTryParse(formatter, "", Optional.empty()),

                        testTryParse(formatter, "127.0.0.1", Optional.of(IPv4Address.LOCALHOST)),
                        testTryParse(formatter, "0.0.0.0", Optional.of(IPv4Address.MIN_VALUE)),
                        testTryParse(formatter, "255.255.255.255", Optional.of(IPv4Address.MAX_VALUE)),
                        testTryParse(formatter, "12.34.56.78", Optional.of(IPv4Address.valueOf(12, 34, 56, 78))),

                        testTryParse(formatter, "::1", Optional.of(IPv6Address.LOCALHOST)),
                        testTryParse(formatter, "::", Optional.of(IPv6Address.MIN_VALUE)),
                        testTryParse(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Optional.of(IPv6Address.MAX_VALUE)),

                        testTryParse(formatter, "12:34:56:78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56:78:90:ab:cd::",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0))),
                        testTryParse(formatter, "12:34:56:78:90:ab::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0))),
                        testTryParse(formatter, "12:34:56:78:90::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0))),
                        testTryParse(formatter, "12:34:56:78::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0))),
                        testTryParse(formatter, "12:34:56::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0))),
                        testTryParse(formatter, "12:34::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0))),
                        testTryParse(formatter, "12::", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0))),

                        testTryParse(formatter, "12:34:56:78:90:ab::ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56:78:90::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56:78::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34:56::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12:34::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "12::ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF))),
                        testTryParse(formatter, "::ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF))),

                        testTryParse(formatter, "12:34:56:78:90::cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56:78::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF))),
                        testTryParse(formatter, "::cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56:78:90::192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56:78::192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56:78::ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34:56::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56:78::ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34:56::ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34:56::90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12:34::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34:56::90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12:34::90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12:34::78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "12::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12:34::78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "12::78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "12::56:78:90:ab:cd:ef",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                        testTryParse(formatter, "::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                        testTryParse(formatter, "12::56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                        testTryParse(formatter, "::56:78:90:ab:192.168.0.1",
                                Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                        testTryParse(formatter, "[::]", Optional.of(IPv6Address.MIN_VALUE)),

                        testTryParse(formatter, ".34.56.78", Optional.empty()),
                        testTryParse(formatter, "12..56.78", Optional.empty()),
                        testTryParse(formatter, "12.34..78", Optional.empty()),
                        testTryParse(formatter, "12.34.56.", Optional.empty()),
                        testTryParse(formatter, "1234.456.789.0", Optional.empty()),
                        testTryParse(formatter, "123.456.789.0", Optional.empty()),
                        testTryParse(formatter, "12.34.56.789", Optional.empty()),
                        testTryParse(formatter, "12.34.56", Optional.empty()),

                        testTryParse(formatter, "z::", Optional.empty()),
                        testTryParse(formatter, "[::", Optional.empty()),
                        testTryParse(formatter, "[::;", Optional.empty()),
                        testTryParse(formatter, "12:::", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:0:0", Optional.empty()),
                        testTryParse(formatter, "0:0:0:0:0:0:0;", Optional.empty()),
                        testTryParse(formatter, "::192.", Optional.empty()),

                        testTryParse(formatter, "192.168.0.1:8080", Optional.empty()),
                };
            }

            private DynamicTest testTryParse(IPAddressFormatter<IPAddress<?>> formatter, String source, Optional<IPAddress<?>> expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(expected, formatter.tryParse(source));
                    assertEquals(expected, formatter.tryParse("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.tryParse("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParse(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parseToBytes(CharSequence) and parseToBytes(CharSequence, int, int)")
            DynamicTest[] testParseToBytes() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null));
                            assertThrows(NullPointerException.class, () -> formatter.parseToBytes(null, 0, 0));
                        }),
                        testParseToBytesInvalid(formatter, "", 0),

                        testParseToBytes(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                        testParseToBytes(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                        testParseToBytes(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }),
                        testParseToBytes(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),

                        testParseToBytes(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testParseToBytes(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testParseToBytes(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytes(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytes(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytes(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytes(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytes(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytes(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesInvalid(formatter, ".34.56.78", 0),
                        testParseToBytesInvalid(formatter, "12..56.78", 3),
                        testParseToBytesInvalid(formatter, "12.34..78", 6),
                        testParseToBytesInvalid(formatter, "12.34.56.", 9),
                        testParseToBytesInvalid(formatter, "1234.456.789.0", 3),
                        testParseToBytesInvalid(formatter, "123.456.789.0", 6),
                        testParseToBytesInvalid(formatter, "12.34.56.789", 11),
                        testParseToBytesInvalid(formatter, "12.34.56", 8),

                        testParseToBytesInvalid(formatter, "z::", 0),
                        testParseToBytesInvalid(formatter, "[::", 3),
                        testParseToBytesInvalid(formatter, "[::;", 3),
                        testParseToBytesInvalid(formatter, "12:::", 4),
                        testParseToBytesInvalid(formatter, "0:0:0:0:", 8),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:", 10),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:0:0", 13),
                        testParseToBytesInvalid(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseToBytesInvalid(formatter, "::192.", 6),

                        testParseToBytesInvalid(formatter, "192.168.0.1:8080", 11),
                };
            }

            private DynamicTest testParseToBytes(IPAddressFormatter<IPAddress<?>> formatter, String source, byte[] expected) {
                return dynamicTest(source, () -> {
                    assertArrayEquals(expected, formatter.parseToBytes(source));
                    assertArrayEquals(expected, formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertArrayEquals(expected, formatter.parseToBytes("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, -1));
                });
            }

            private DynamicTest testParseToBytesInvalid(IPAddressFormatter<IPAddress<?>> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParseException exception = assertThrows(ParseException.class, () -> formatter.parseToBytes(source));
                    assertEquals(errorIndex, exception.getErrorOffset());
                    assertEquals(Messages.IPAddress.parseError(source), exception.getMessage());

                    exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(errorIndex + 1, exception.getErrorOffset());

                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("parseToBytes(CharSequence, ParsePosition)")
            DynamicTest[] testParseToBytesWithPosition() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null, new ParsePosition(0)))),
                        dynamicTest("null position", () -> assertThrows(NullPointerException.class, () -> formatter.parseToBytes("127.0.0.1", null))),
                        testParseToBytesInvalidWithPosition(formatter, "", 0),

                        testParseToBytesWithPosition(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                        testParseToBytesWithPosition(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                        testParseToBytesWithPosition(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255}),
                        testParseToBytesWithPosition(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),

                        testParseToBytesWithPosition(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testParseToBytesWithPosition(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testParseToBytesWithPosition(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testParseToBytesWithPosition(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testParseToBytesWithPosition(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testParseToBytesWithPosition(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testParseToBytesWithPosition(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testParseToBytesWithPosition(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testParseToBytesInvalidWithPosition(formatter, ".34.56.78", 0),
                        testParseToBytesInvalidWithPosition(formatter, "12..56.78", 3),
                        testParseToBytesInvalidWithPosition(formatter, "12.34..78", 6),
                        testParseToBytesInvalidWithPosition(formatter, "12.34.56.", 9),
                        testParseToBytesInvalidWithPosition(formatter, "1234.456.789.0", 3),
                        testParseToBytesInvalidWithPosition(formatter, "123.456.789.0", 6),
                        testParseToBytesWithPosition(formatter, "12.34.56.789", new byte[] { 12, 34, 56, 78, }, 11),
                        testParseToBytesInvalidWithPosition(formatter, "12.34.56", 8),

                        testParseToBytesInvalidWithPosition(formatter, "z::", 0),
                        testParseToBytesInvalidWithPosition(formatter, "[::", 3),
                        testParseToBytesInvalidWithPosition(formatter, "[::;", 3),
                        testParseToBytesWithPosition(formatter, "12:::", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }, 4),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:", 8),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:", 10),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:0:0", 13),
                        testParseToBytesInvalidWithPosition(formatter, "0:0:0:0:0:0:0;", 13),
                        testParseToBytesWithPosition(formatter, "::192.", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 146,
                        }, 5),

                        testParseToBytesWithPosition(formatter, "192.168.0.1:8080", new byte[] { (byte) 192, (byte) 168, 0, 1, }, 11),
                };
            }

            private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source, byte[] expected) {
                return testParseToBytesWithPosition(formatter, source, expected, source.length());
            }

            private DynamicTest testParseToBytesWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source,
                    byte[] expected, int expectedIndex) {

                return dynamicTest(source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    byte[] address = formatter.parseToBytes(source, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String postfix = "z2345";
                    position.setIndex(0);
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(source + postfix, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(expectedIndex, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(prefix + source + postfix, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());

                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    address = formatter.parseToBytes(prefix + source, position);
                    assertArrayEquals(expected, address);
                    assertEquals(-1, position.getErrorIndex());
                    assertEquals(prefix.length() + expectedIndex, position.getIndex());
                });
            }

            private DynamicTest testParseToBytesInvalidWithPosition(IPAddressFormatter<IPAddress<?>> formatter, String source, int errorIndex) {
                return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                    ParsePosition position = new ParsePosition(0);
                    assertNull(formatter.parseToBytes(source, position));
                    assertEquals(errorIndex, position.getErrorIndex());
                    assertEquals(0, position.getIndex());

                    String prefix = "12345";
                    position.setIndex(prefix.length());
                    position.setErrorIndex(-1);
                    assertNull(formatter.parseToBytes(prefix + source, position));
                    assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                    assertEquals(prefix.length(), position.getIndex());
                });
            }

            @TestFactory
            @DisplayName("tryParseToBytes")
            DynamicTest[] testTryParseToBytes() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> {
                            assertEquals(Optional.empty(), formatter.tryParseToBytes(null));
                            assertEquals(Optional.empty(), formatter.tryParseToBytes(null, 0, 0));
                        }),
                        testTryParseToBytesEmptyOptional(formatter, ""),

                        testTryParseToBytes(formatter, "127.0.0.1", new byte[] { 127, 0, 0, 1, }),
                        testTryParseToBytes(formatter, "0.0.0.0", new byte[] { 0, 0, 0, 0, }),
                        testTryParseToBytes(formatter, "255.255.255.255", new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, }),
                        testTryParseToBytes(formatter, "12.34.56.78", new byte[] { 12, 34, 56, 78, }),

                        testTryParseToBytes(formatter, "::1", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, }),
                        testTryParseToBytes(formatter, "::", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),
                        testTryParseToBytes(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", new byte[] {
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab:cd::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90:ab::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12:34::", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        }),
                        testTryParseToBytes(formatter, "12::", new byte[] { 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testTryParseToBytes(formatter, "12:34:56:78:90:ab::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78:90::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78:90::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, (byte) 144, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56:78::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56:78::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 120, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34:56::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34:56::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12:34::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34:56::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 86, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12:34::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12:34::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "12::78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12:34::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 52, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "12::78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 0, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "12::56:78:90:ab:cd:ef", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),
                        testTryParseToBytes(formatter, "::56:78:90:ab:cd:ef", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, 0, (byte) 205, 0, (byte) 239,
                        }),

                        testTryParseToBytes(formatter, "12::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 18, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),
                        testTryParseToBytes(formatter, "::56:78:90:ab:192.168.0.1", new byte[] {
                                0, 0, 0, 0, 0, 86, 0, 120, 0, (byte) 144, 0, (byte) 171, (byte) 192, (byte) 168, 0, 1,
                        }),

                        testTryParseToBytes(formatter, "[::]", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }),

                        testTryParseToBytesEmptyOptional(formatter, ".34.56.78"),
                        testTryParseToBytesEmptyOptional(formatter, "12..56.78"),
                        testTryParseToBytesEmptyOptional(formatter, "12.34..78"),
                        testTryParseToBytesEmptyOptional(formatter, "12.34.56."),
                        testTryParseToBytesEmptyOptional(formatter, "1234.456.789.0"),
                        testTryParseToBytesEmptyOptional(formatter, "123.456.789.0"),
                        testTryParseToBytesEmptyOptional(formatter, "12.34.56.789"),
                        testTryParseToBytesEmptyOptional(formatter, "12.34.56"),

                        testTryParseToBytesEmptyOptional(formatter, "z::"),
                        testTryParseToBytesEmptyOptional(formatter, "[::"),
                        testTryParseToBytesEmptyOptional(formatter, "[::;"),
                        testTryParseToBytesEmptyOptional(formatter, "12:::"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:0:0"),
                        testTryParseToBytesEmptyOptional(formatter, "0:0:0:0:0:0:0;"),
                        testTryParseToBytesEmptyOptional(formatter, "::192."),

                        testTryParseToBytesEmptyOptional(formatter, "192.168.0.1:8080"),
                };
            }

            private DynamicTest testTryParseToBytes(IPAddressFormatter<IPAddress<?>> formatter, String source, byte[] expected) {
                return dynamicTest(source, () -> {
                    assertArrayEquals(expected, formatter.tryParseToBytes(source).get());
                    assertArrayEquals(expected, formatter.tryParseToBytes("1" + source + "1", 1, 1 + source.length()).get());
                    assertArrayEquals(expected, formatter.tryParseToBytes("z" + source + "z", 1, 1 + source.length()).get());
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
                });
            }

            private DynamicTest testTryParseToBytesEmptyOptional(IPAddressFormatter<IPAddress<?>> formatter, String source) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(Optional.empty(), formatter.tryParseToBytes(source));
                    assertEquals(Optional.empty(), formatter.tryParseToBytes("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(Optional.empty(), formatter.tryParseToBytes("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.tryParseToBytes(source, 0, -1));
                });
            }

            @Nested
            @DisplayName("asFormat")
            class AsFormat {

                @TestFactory
                @DisplayName("parseObject(String)")
                DynamicTest[] testParseObject() {
                    IPAddressFormat<IPAddress<?>> format = IPAddressFormatter.anyVersionWithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null))),
                            testParseObjectInvalid(format, "", 0),

                            testParseObject(format, "127.0.0.1", IPv4Address.LOCALHOST),
                            testParseObject(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                            testParseObject(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                            testParseObject(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),
                            // parsing stops after 78
                            testParseObject(format, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78)),

                            testParseObject(format, "::1", IPv6Address.LOCALHOST),
                            testParseObject(format, "::", IPv6Address.MIN_VALUE),
                            testParseObject(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParseObject(format, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParseObject(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParseObject(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParseObject(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParseObject(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParseObject(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParseObject(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParseObject(format, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParseObject(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParseObject(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObject(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParseObject(format, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObject(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObject(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObject(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObject(format, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObject(format, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObject(format, "[::]", IPv6Address.MIN_VALUE),
                            // parsing stops after :: for the next two
                            testParseObject(format, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),
                            testParseObject(format, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192)),
                            // parsing stops after the 0.1
                            testParseObject(format, "192.168.0.1:8080", IPv4Address.valueOf(192, 168, 0, 1)),

                            testParseObjectInvalid(format, ".34.56.78", 0),
                            testParseObjectInvalid(format, "12..56.78", 3),
                            testParseObjectInvalid(format, "12.34..78", 6),
                            testParseObjectInvalid(format, "12.34.56.", 9),
                            testParseObjectInvalid(format, "1234.456.789.0", 3),
                            testParseObjectInvalid(format, "123.456.789.0", 6),
                            testParseObjectInvalid(format, "12.34.56", 8),

                            testParseObjectInvalid(format, "z::", 0),
                            testParseObjectInvalid(format, "[::", 3),
                            testParseObjectInvalid(format, "[::;", 3),
                            testParseObjectInvalid(format, "0:0:0:0:", 8),
                            testParseObjectInvalid(format, "0:0:0:0:0:", 10),
                            testParseObjectInvalid(format, "0:0:0:0:0:0:0", 13),
                            testParseObjectInvalid(format, "0:0:0:0:0:0:0;", 13),
                    };
                }

                private DynamicTest testParseObject(IPAddressFormat<IPAddress<?>> format, String source, IPAddress<?> expected) {
                    return dynamicTest(source, () -> assertEquals(expected, format.parseObject(source)));
                }

                private DynamicTest testParseObjectInvalid(IPAddressFormat<IPAddress<?>> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParseException exception = assertThrows(ParseException.class, () -> format.parseObject(source));
                        assertEquals(errorIndex, exception.getErrorOffset());
                    });
                }

                @TestFactory
                @DisplayName("parseObject(String, ParsePosition)")
                DynamicTest[] testParseObjectWithPosition() {
                    IPAddressFormat<IPAddress<?>> format = IPAddressFormatter.anyVersionWithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parseObject(null))),
                            testParseObjectInvalidWithPosition(format, "", 0),

                            testParseObjectWithPosition(format, "127.0.0.1", IPv4Address.LOCALHOST),
                            testParseObjectWithPosition(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                            testParseObjectWithPosition(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                            testParseObjectWithPosition(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),

                            testParseObjectWithPosition(format, "::1", IPv6Address.LOCALHOST),
                            testParseObjectWithPosition(format, "::", IPv6Address.MIN_VALUE),
                            testParseObjectWithPosition(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab:cd::",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParseObjectWithPosition(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParseObjectWithPosition(format, "12:34:56:78:90:ab::ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParseObjectWithPosition(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78:90::cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78:90::192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56:78::192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56:78::ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56:78::ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34:56::ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34:56::90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34:56::90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12:34::90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12:34::78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12:34::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "12::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "12::56:78:90:ab:cd:ef",
                                    IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParseObjectWithPosition(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParseObjectWithPosition(format, "12::56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParseObjectWithPosition(format, "::56:78:90:ab:192.168.0.1",
                                    IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParseObjectWithPosition(format, "[::]", IPv6Address.MIN_VALUE),

                            testParseObjectInvalidWithPosition(format, ".34.56.78", 0),
                            testParseObjectInvalidWithPosition(format, "12..56.78", 3),
                            testParseObjectInvalidWithPosition(format, "12.34..78", 6),
                            testParseObjectInvalidWithPosition(format, "12.34.56.", 9),
                            testParseObjectInvalidWithPosition(format, "1234.456.789.0", 3),
                            testParseObjectInvalidWithPosition(format, "123.456.789.0", 6),
                            testParseObjectWithPosition(format, "12.34.56.789", IPv4Address.valueOf(12, 34, 56, 78), 11),
                            testParseObjectInvalidWithPosition(format, "12.34.56", 8),

                            testParseObjectInvalidWithPosition(format, "z::", 0),
                            testParseObjectInvalidWithPosition(format, "[::", 3),
                            testParseObjectInvalidWithPosition(format, "[::;", 3),
                            testParseObjectWithPosition(format, "12:::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0), 4),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:", 8),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:", 10),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:0:0", 13),
                            testParseObjectInvalidWithPosition(format, "0:0:0:0:0:0:0;", 13),
                            testParseObjectWithPosition(format, "::192.", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0x192), 5),

                            testParseObjectWithPosition(format, "192.168.0.1:8080", IPv4Address.valueOf(192, 168, 0, 1), 11),
                    };
                }

                private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPAddress<?>> format, String source, IPAddress<?> expected) {
                    return testParseObjectWithPosition(format, source, expected, source.length());
                }

                private DynamicTest testParseObjectWithPosition(IPAddressFormat<IPAddress<?>> format, String source, IPAddress<?> expected,
                        int expectedIndex) {

                    return dynamicTest(source, () -> {
                        ParsePosition position = new ParsePosition(0);
                        IPAddress<?> address = format.parseObject(source, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(expectedIndex, position.getIndex());

                        String postfix = "z2345";
                        position.setIndex(0);
                        position.setErrorIndex(-1);
                        address = format.parseObject(source + postfix, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(expectedIndex, position.getIndex());

                        String prefix = "12345";
                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        address = format.parseObject(prefix + source + postfix, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(prefix.length() + expectedIndex, position.getIndex());

                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        address = format.parseObject(prefix + source, position);
                        assertEquals(expected, address);
                        assertEquals(-1, position.getErrorIndex());
                        assertEquals(prefix.length() + expectedIndex, position.getIndex());
                    });
                }

                private DynamicTest testParseObjectInvalidWithPosition(IPAddressFormat<IPAddress<?>> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParsePosition position = new ParsePosition(0);
                        assertNull(format.parseObject(source, position));
                        assertEquals(errorIndex, position.getErrorIndex());
                        assertEquals(0, position.getIndex());

                        String prefix = "12345";
                        position.setIndex(prefix.length());
                        position.setErrorIndex(-1);
                        assertNull(format.parseObject(prefix + source, position));
                        assertEquals(errorIndex + prefix.length(), position.getErrorIndex());
                        assertEquals(prefix.length(), position.getIndex());
                    });
                }

                // parse(CharSequence source, ParsePosition position) is tested through parseObject

                @TestFactory
                @DisplayName("parse(CharSequence)")
                DynamicTest[] testParse() {
                    IPAddressFormat<IPAddress<?>> format = IPAddressFormatter.anyVersionWithDefaults().asFormat();
                    return new DynamicTest[] {
                            dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> format.parse(null))),
                            testParseInvalid(format, "", 0),

                            testParse(format, "127.0.0.1", IPv4Address.LOCALHOST),
                            testParse(format, "0.0.0.0", IPv4Address.MIN_VALUE),
                            testParse(format, "255.255.255.255", IPv4Address.MAX_VALUE),
                            testParse(format, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),

                            testParse(format, "::1", IPv6Address.LOCALHOST),
                            testParse(format, "::", IPv6Address.MIN_VALUE),
                            testParse(format, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                            testParse(format, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                            testParse(format, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                            testParse(format, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                            testParse(format, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                            testParse(format, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                            testParse(format, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                            testParse(format, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                            testParse(format, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                            testParse(format, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                            testParse(format, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                            testParse(format, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                            testParse(format, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                            testParse(format, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                            testParse(format, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                            testParse(format, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                            testParse(format, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                            testParse(format, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                            testParse(format, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                            testParse(format, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                            testParse(format, "[::]", IPv6Address.MIN_VALUE),

                            testParseInvalid(format, ".34.56.78", 0),
                            testParseInvalid(format, "12..56.78", 3),
                            testParseInvalid(format, "12.34..78", 6),
                            testParseInvalid(format, "12.34.56.", 9),
                            testParseInvalid(format, "1234.456.789.0", 3),
                            testParseInvalid(format, "123.456.789.0", 6),
                            testParseInvalid(format, "12.34.56.789", 11),
                            testParseInvalid(format, "12.34.56", 8),

                            testParseInvalid(format, "z::", 0),
                            testParseInvalid(format, "[::", 3),
                            testParseInvalid(format, "[::;", 3),
                            testParseInvalid(format, "12:::", 4),
                            testParseInvalid(format, "0:0:0:0:", 8),
                            testParseInvalid(format, "0:0:0:0:0:", 10),
                            testParseInvalid(format, "0:0:0:0:0:0:0", 13),
                            testParseInvalid(format, "0:0:0:0:0:0:0;", 13),
                            testParseInvalid(format, "::192.", 6),

                            testParseInvalid(format, "192.168.0.1:8080", 11),
                    };
                }

                private DynamicTest testParse(IPAddressFormat<IPAddress<?>> format, String source, IPAddress<?> expected) {
                    return dynamicTest(source, () -> assertEquals(expected, format.parse(source)));
                }

                private DynamicTest testParseInvalid(IPAddressFormat<IPAddress<?>> format, String source, int errorIndex) {
                    return dynamicTest(source.isEmpty() ? "empty" : source, () -> {
                        ParseException exception = assertThrows(ParseException.class, () -> format.parse(source));
                        assertEquals(errorIndex, exception.getErrorOffset());
                    });
                }
            }

            @TestFactory
            @DisplayName("isValid")
            DynamicTest[] testIsValid() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        dynamicTest("null", () -> assertEquals(false, formatter.isValid(null, 0, 0))),
                        testIsValid(formatter, "", false),

                        testIsValid(formatter, "127.0.0.1", true),
                        testIsValid(formatter, "0.0.0.0", true),
                        testIsValid(formatter, "255.255.255.255", true),
                        testIsValid(formatter, "12.34.56.78", true),

                        testIsValid(formatter, "::1", true),
                        testIsValid(formatter, "::", true),
                        testIsValid(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),

                        testIsValid(formatter, "12:34:56:78:90:ab:cd:ef", true),
                        testIsValid(formatter, "12:34:56:78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34:56:78:90:ab:cd::", true),
                        testIsValid(formatter, "12:34:56:78:90:ab::", true),
                        testIsValid(formatter, "12:34:56:78:90::", true),
                        testIsValid(formatter, "12:34:56:78::", true),
                        testIsValid(formatter, "12:34:56::", true),
                        testIsValid(formatter, "12:34::", true),
                        testIsValid(formatter, "12::", true),

                        testIsValid(formatter, "12:34:56:78:90:ab::ef", true),
                        testIsValid(formatter, "12:34:56:78:90::ef", true),
                        testIsValid(formatter, "12:34:56:78::ef", true),
                        testIsValid(formatter, "12:34:56::ef", true),
                        testIsValid(formatter, "12:34::ef", true),
                        testIsValid(formatter, "12::ef", true),
                        testIsValid(formatter, "::ef", true),

                        testIsValid(formatter, "12:34:56:78:90::cd:ef", true),
                        testIsValid(formatter, "12:34:56:78::cd:ef", true),
                        testIsValid(formatter, "12:34:56::cd:ef", true),
                        testIsValid(formatter, "12:34::cd:ef", true),
                        testIsValid(formatter, "12::cd:ef", true),
                        testIsValid(formatter, "::cd:ef", true),

                        testIsValid(formatter, "12:34:56:78:90::192.168.0.1", true),
                        testIsValid(formatter, "12:34:56:78::192.168.0.1", true),
                        testIsValid(formatter, "12:34:56::192.168.0.1", true),
                        testIsValid(formatter, "12:34::192.168.0.1", true),
                        testIsValid(formatter, "12::192.168.0.1", true),
                        testIsValid(formatter, "::192.168.0.1", true),

                        testIsValid(formatter, "12:34:56:78::ab:cd:ef", true),
                        testIsValid(formatter, "12:34:56::ab:cd:ef", true),
                        testIsValid(formatter, "12:34::ab:cd:ef", true),
                        testIsValid(formatter, "12::ab:cd:ef", true),
                        testIsValid(formatter, "::ab:cd:ef", true),

                        testIsValid(formatter, "12:34:56:78::ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34:56::ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34::ab:192.168.0.1", true),
                        testIsValid(formatter, "12::ab:192.168.0.1", true),
                        testIsValid(formatter, "::ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34:56::90:ab:cd:ef", true),
                        testIsValid(formatter, "12:34::90:ab:cd:ef", true),
                        testIsValid(formatter, "12::90:ab:cd:ef", true),
                        testIsValid(formatter, "::90:ab:cd:ef", true),

                        testIsValid(formatter, "12:34:56::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12:34::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12::90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12:34::78:90:ab:cd:ef", true),
                        testIsValid(formatter, "12::78:90:ab:cd:ef", true),
                        testIsValid(formatter, "::78:90:ab:cd:ef", true),

                        testIsValid(formatter, "12:34::78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "12::78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "12::56:78:90:ab:cd:ef", true),
                        testIsValid(formatter, "::56:78:90:ab:cd:ef", true),

                        testIsValid(formatter, "12::56:78:90:ab:192.168.0.1", true),
                        testIsValid(formatter, "::56:78:90:ab:192.168.0.1", true),

                        testIsValid(formatter, "[::]", true),

                        testIsValid(formatter, ".34.56.78", false),
                        testIsValid(formatter, "12..56.78", false),
                        testIsValid(formatter, "12.34..78", false),
                        testIsValid(formatter, "12.34.56.", false),
                        testIsValid(formatter, "1234.456.789.0", false),
                        testIsValid(formatter, "123.456.789.0", false),
                        testIsValid(formatter, "12.34.56.789", false),
                        testIsValid(formatter, "12.34.56", false),

                        testIsValid(formatter, "z::", false),
                        testIsValid(formatter, "[::", false),
                        testIsValid(formatter, "[::;", false),
                        testIsValid(formatter, "12:::", false),
                        testIsValid(formatter, "0:0:0:0:", false),
                        testIsValid(formatter, "0:0:0:0:0:", false),
                        testIsValid(formatter, "0:0:0:0:0:0:0", false),
                        testIsValid(formatter, "0:0:0:0:0:0:0;", false),
                        testIsValid(formatter, "::192.", false),

                        testIsValid(formatter, "192.168.0.1:8080", false),
                };
            }

            private DynamicTest testIsValid(IPAddressFormatter<IPAddress<?>> formatter, String source, boolean expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    assertEquals(expected, formatter.isValid(source, 0, source.length()));
                    assertEquals(expected, formatter.isValid("1" + source + "1", 1, 1 + source.length()));
                    assertEquals(expected, formatter.isValid("z" + source + "z", 1, 1 + source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, -1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, source.length() + 1));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, source.length() + 1, source.length()));
                    assertThrows(IndexOutOfBoundsException.class, () -> formatter.isValid(source, 0, -1));
                });
            }

            @TestFactory
            @DisplayName("testIfValid")
            DynamicTest[] testTestIfValid() {
                IPAddressFormatter<IPAddress<?>> formatter = IPAddressFormatter.anyVersionWithDefaults();
                return new DynamicTest[] {
                        testTestIfValid(formatter, null, null),
                        testTestIfValid(formatter, "", null),

                        testTestIfValid(formatter, "127.0.0.1", IPv4Address.LOCALHOST),
                        testTestIfValid(formatter, "0.0.0.0", IPv4Address.MIN_VALUE),
                        testTestIfValid(formatter, "255.255.255.255", IPv4Address.MAX_VALUE),
                        testTestIfValid(formatter, "12.34.56.78", IPv4Address.valueOf(12, 34, 56, 78)),

                        testTestIfValid(formatter, "::1", IPv6Address.LOCALHOST),
                        testTestIfValid(formatter, "::", IPv6Address.MIN_VALUE),
                        testTestIfValid(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                        testTestIfValid(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78:90:ab:192.168.0.1",
                                IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56:78:90:ab:cd::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0)),
                        testTestIfValid(formatter, "12:34:56:78:90:ab::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0)),
                        testTestIfValid(formatter, "12:34:56:78:90::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34:56:78::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34:56::", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12:34::", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0)),
                        testTestIfValid(formatter, "12::", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0)),

                        testTestIfValid(formatter, "12:34:56:78:90:ab::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78:90::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12:34::ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "12::ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF)),
                        testTestIfValid(formatter, "::ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78:90::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56:78::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78:90::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56:78::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56:78::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34:56::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56:78::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34:56::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34:56::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12:34::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34:56::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12:34::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12:34::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "12::78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12:34::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "12::78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "12::56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                        testTestIfValid(formatter, "::56:78:90:ab:cd:ef", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),

                        testTestIfValid(formatter, "12::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),
                        testTestIfValid(formatter, "::56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

                        testTestIfValid(formatter, "[::]", IPv6Address.MIN_VALUE),

                        testTestIfValid(formatter, ".34.56.78", null),
                        testTestIfValid(formatter, "12..56.78", null),
                        testTestIfValid(formatter, "12.34..78", null),
                        testTestIfValid(formatter, "12.34.56.", null),
                        testTestIfValid(formatter, "1234.456.789.0", null),
                        testTestIfValid(formatter, "123.456.789.0", null),
                        testTestIfValid(formatter, "12.34.56.789", null),
                        testTestIfValid(formatter, "12.34.56", null),

                        testTestIfValid(formatter, "z::", null),
                        testTestIfValid(formatter, "[::", null),
                        testTestIfValid(formatter, "[::;", null),
                        testTestIfValid(formatter, "12:::", null),
                        testTestIfValid(formatter, "0:0:0:0:", null),
                        testTestIfValid(formatter, "0:0:0:0:0:", null),
                        testTestIfValid(formatter, "0:0:0:0:0:0:0", null),
                        testTestIfValid(formatter, "0:0:0:0:0:0:0;", null),
                        testTestIfValid(formatter, "::192.", null),

                        testTestIfValid(formatter, "192.168.0.1:8080", null),
                };
            }

            private DynamicTest testTestIfValid(IPAddressFormatter<IPAddress<?>> formatter, String source, IPAddress<?> expected) {
                String displayName = String.valueOf(source);
                return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> {
                    testTestIfValid(formatter, source, expected, true);
                    testTestIfValid(formatter, source, expected, false);
                });
            }

            @SuppressWarnings("unchecked")
            private void testTestIfValid(IPAddressFormatter<IPAddress<?>> formatter, String source, IPAddress<?> expected, boolean testResult) {
                Predicate<? super IPAddress<?>> predicate = mock(Predicate.class);
                when(predicate.test(any())).thenReturn(testResult);

                boolean result = formatter.testIfValid(source, predicate);
                if (expected != null) {
                    assertEquals(testResult, result);
                    verify(predicate).test(expected);
                } else {
                    assertEquals(false, result);
                }
                verifyNoMoreInteractions(predicate);
            }
        }
    }

    private static final class TestIPAddress extends IPAddress<TestIPAddress> {

        @Override
        public int compareTo(TestIPAddress o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int bits() {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] toByteArray() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean equals(Object o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int hashCode() {
            throw new UnsupportedOperationException();
        }

        @Override
        String format() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isMulticastAddress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isWildcardAddress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isLoopbackAddress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isLinkLocalAddress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isSiteLocalAddress() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean hasNext() {
            throw new UnsupportedOperationException();
        }

        @Override
        public TestIPAddress next() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean hasPrevious() {
            throw new UnsupportedOperationException();
        }

        @Override
        public TestIPAddress previous() {
            throw new UnsupportedOperationException();
        }

        @Override
        public IPRange<TestIPAddress> to(TestIPAddress end) {
            throw new UnsupportedOperationException();
        }

        @Override
        public IPRange<TestIPAddress> asRange() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Subnet<TestIPAddress> inSubnet(int prefixLength) {
            throw new UnsupportedOperationException();
        }

        @Override
        Subnet<TestIPAddress> startingSubnet(int prefixLength) {
            throw new UnsupportedOperationException();
        }

        @Override
        boolean isValidRoutingPrefix(int prefixLength) {
            throw new UnsupportedOperationException();
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T assertSerializable(T object) throws IOException, ClassNotFoundException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(object);
        }
        byte[] bytes = baos.toByteArray();
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return (T) ois.readObject();
        }
    }
}
