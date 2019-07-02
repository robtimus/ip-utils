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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import java.text.ParseException;
import java.text.ParsePosition;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import com.github.robtimus.net.ip.IPAddressFormatter.Builder;

@SuppressWarnings({ "javadoc", "nls" })
public class IPAddressFormatterTest {

    @TestFactory
    public DynamicTest[] testIPv6() {
        IPv6Address address = IPv6Address.valueOf(1, 2, 3, 0, 0, 0, 0xFFAB, 0x1234);
        return new DynamicTest[] {
                testIPv6("unmodifier", IPAddressFormatter.ipv6(), address, "1:2:3::ffab:1234"),
                testIPv6("withDefaults", IPAddressFormatter.ipv6().withDefaults(), address, "1:2:3::ffab:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3::ffab:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3::ffab:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3::255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3::255.171.18.52]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3::FFAB:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3::FFAB:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3::255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withShortStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3::255.171.18.52]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3:0:0:0:ffab:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3:0:0:0:ffab:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3:0:0:0:255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3:0:0:0:255.171.18.52]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3:0:0:0:FFAB:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3:0:0:0:FFAB:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "1:2:3:0:0:0:255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withMediumStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[1:2:3:0:0:0:255.171.18.52]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "0001:0002:0003:0000:0000:0000:ffab:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[0001:0002:0003:0000:0000:0000:ffab:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "0001:0002:0003:0000:0000:0000:255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[0001:0002:0003:0000:0000:0000:255.171.18.52]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), address, "0001:0002:0003:0000:0000:0000:FFAB:1234"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), address, "[0001:0002:0003:0000:0000:0000:FFAB:1234]"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), address, "0001:0002:0003:0000:0000:0000:255.171.18.52"),
                testIPv6(IPAddressFormatter.ipv6()
                        .withLongStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), address, "[0001:0002:0003:0000:0000:0000:255.171.18.52]"),
        };
    }

    private DynamicTest testIPv6(String displayName, Builder<IPv6Address> builder, IPv6Address address, String expected) {
        return dynamicTest(displayName, () -> {
            IPAddressFormatter<IPv6Address> formatter = builder.build();
            assertEquals(expected, formatter.format(address));
        });
    }

    private DynamicTest testIPv6(Builder<IPv6Address> builder, IPv6Address address, String expected) {
        IPAddressFormatter<IPv6Address> formatter = builder.build();
        return dynamicTest(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), () -> {
            assertEquals(expected, formatter.format(address));
        });
    }

    @TestFactory
    public DynamicTest[] testAnyVersion() {
        IPv6Address ipv6Address = IPv6Address.valueOf(1, 2, 3, 0, 0, 0, 0xFFAB, 0x1234);
        return new DynamicTest[] {
                testAnyVersion("unmodified", IPAddressFormatter.anyVersion(), ipv6Address, "1:2:3::ffab:1234"),
                testAnyVersion("withDefaults", IPAddressFormatter.anyVersion().withDefaults(), ipv6Address, "1:2:3::ffab:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3::ffab:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3::ffab:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3::255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3::255.171.18.52]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3::FFAB:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3::FFAB:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3::255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withShortStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3::255.171.18.52]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3:0:0:0:ffab:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3:0:0:0:ffab:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3:0:0:0:255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3:0:0:0:255.171.18.52]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3:0:0:0:FFAB:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3:0:0:0:FFAB:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "1:2:3:0:0:0:255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withMediumStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[1:2:3:0:0:0:255.171.18.52]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "0001:0002:0003:0000:0000:0000:ffab:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toLowerCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[0001:0002:0003:0000:0000:0000:ffab:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "0001:0002:0003:0000:0000:0000:255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toLowerCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[0001:0002:0003:0000:0000:0000:255.171.18.52]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "0001:0002:0003:0000:0000:0000:FFAB:1234"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toUpperCase()
                        .withoutIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[0001:0002:0003:0000:0000:0000:FFAB:1234]"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .notEnclosingInBrackets(), ipv6Address, "0001:0002:0003:0000:0000:0000:255.171.18.52"),
                testAnyVersion(IPAddressFormatter.anyVersion()
                        .withLongStyle()
                        .toUpperCase()
                        .withIPv4End()
                        .enclosingInBrackets(), ipv6Address, "[0001:0002:0003:0000:0000:0000:255.171.18.52]"),
        };
    }

    private DynamicTest testAnyVersion(String displayName, Builder<IPAddress<?>> builder, IPv6Address ipv6Address, String expectedIPv6) {
        return dynamicTest(displayName, () -> {
            IPAddressFormatter<IPAddress<?>> formatter = builder.build();
            assertEquals("12.34.56.78", formatter.format(IPv4Address.valueOf(12, 34, 56, 78)));
            assertEquals(expectedIPv6, formatter.format(ipv6Address));
        });
    }

    private DynamicTest testAnyVersion(Builder<IPAddress<?>> builder, IPv6Address ipv6Address, String expectedIPv6) {
        IPAddressFormatter<IPAddress<?>> formatter = builder.build();
        return dynamicTest(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), () -> {
            assertEquals("12.34.56.78", formatter.format(IPv4Address.valueOf(12, 34, 56, 78)));
            assertEquals(expectedIPv6, formatter.format(ipv6Address));
        });
    }

    @Nested
    public class IPv4 {

        @TestFactory
        public DynamicTest[] testFormatIPv4Address() {
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
        public DynamicTest[] testFormatBytes() {
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
                assertEquals(Messages.IPAddress.invalidArraySize.get(length), exception.getMessage());
            });
        }

        // valueOf is tested through IPv4AddressTest.testValueOfCharSequence

        @TestFactory
        public DynamicTest[] testParse() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseWithPosition() {
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
        public DynamicTest[] testTryParse() {
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
        public DynamicTest[] testParseToBytes() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseToBytesWithPosition() {
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
        public DynamicTest[] testTryParseToBytes() {
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

        @TestFactory
        public DynamicTest[] testIsValid() {
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
        public DynamicTest[] testTestIfValid() {
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
        public void testToString() {
            IPAddressFormatter<IPv4Address> formatter = IPAddressFormatter.ipv4();
            assertEquals(IPAddressFormatter.class.getName() + "#IPv4", formatter.toString());
        }
    }

    @Nested
    public class IPv6 {

        @TestFactory
        public DynamicContainer[] testFormatIPv4Address() {
            return testFormat(Function.identity(), new Formatters<>(IPAddressFormatter::format, IPAddressFormatter::format));
        }

        @TestFactory
        public DynamicContainer[] testFormatBytes() {
            return testFormat(IPv6Address::toByteArray, new Formatters<>(IPAddressFormatter::format, IPAddressFormatter::format),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 0),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 4),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 15),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 17));
        }

        @SafeVarargs
        private final <T> DynamicContainer[] testFormat(Function<IPv6Address, T> mapper,
                Formatters<IPv6Address, T> formatters,
                Function<IPAddressFormatter<IPv6Address>, DynamicTest>... additionalTests) {

            return new DynamicContainer[] {
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::", "::1", "1::", "123:456:789:100:abcd:ef00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:abcd:ef00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::", "::1", "1::", "123:456:789:100:ABCD:EF00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:ABCD:EF00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:abcd:ef00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:abcd:ef00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:ABCD:EF00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:ABCD:EF00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:abcd:ef00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:abcd:ef00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:abcd:ef00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:abcd:ef00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:ABCD:EF00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:ABCD:EF00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:ABCD:EF00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:ABCD:EF00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]",
                            additionalTests),
            };
        }

        @SafeVarargs
        private final <T> DynamicContainer testFormat(Builder<IPv6Address> builder, Function<IPv6Address, T> mapper,
                Formatters<IPv6Address, T> formatters, String expected1,
                String expected2, String expected3, String expected4, String expected5, String expected6, String expected7,
                Function<IPAddressFormatter<IPv6Address>, DynamicTest>... additionalTests) {

            IPAddressFormatter<IPv6Address> formatter = builder.build();
            DynamicTest[] tests = {
                    dynamicTest("null", () -> formatters.testNull(formatter)),
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0L, 0L), expected1),
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0L, 1L), expected2),
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x0001000000000000L, 0L), expected3),
                    // no zeroes sections
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x0123045607890100L, 0xABCDEF0010000001L), expected4),
                    // one zeroes sections
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000000000L, 0x0000123400010001L), expected5),
                    // two zeroes sections, the first one being the longest
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000000000L, 0x0000123400000000L), expected6),
                    // two zeroes sections, the second one being the longest
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000001234L, 0x5678000000000000L), expected7),
            };
            if (additionalTests.length > 0) {
                tests = Stream.concat(
                        Arrays.stream(tests),
                        Arrays.stream(additionalTests).map(f -> f.apply(formatter))
                ).toArray(DynamicTest[]::new);
            }
            return dynamicContainer(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), Arrays.asList(tests));
        }

        private <T> DynamicTest testFormat(IPAddressFormatter<IPv6Address> formatter, Function<IPv6Address, T> mapper,
                Formatters<IPv6Address, T> formatters, IPv6Address address, String expected) {

            return dynamicTest(address.toString(), () -> formatters.test(formatter, mapper.apply(address), expected));
        }

        private DynamicTest testFormatBytesOfInvalidLength(IPAddressFormatter<IPv6Address> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize.get(length), exception.getMessage());
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length], new StringBuilder()));
                assertEquals(Messages.IPAddress.invalidArraySize.get(length), exception.getMessage());
            });
        }

        // valueOf is tested through IPv6AddressTest.testValueOfCharSequence

        @TestFactory
        public DynamicTest[] testParse() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseWithPosition() {
            IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
            return new DynamicTest[] {
                    dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> formatter.parse(null))),
                    testParseInvalidWithPosition(formatter, "", 0),

                    testParseWithPosition(formatter, "::1", IPv6Address.LOCALHOST),
                    testParseWithPosition(formatter, "::", IPv6Address.MIN_VALUE),
                    testParseWithPosition(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                    testParseWithPosition(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
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

        private DynamicTest testParseWithPosition(IPAddressFormatter<IPv6Address> formatter, String source, IPv6Address expected, int expectedIndex) {
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
        public DynamicTest[] testTryParse() {
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

                    testTryParse(formatter, "12:34:56:78:90:ab:cd::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0))),
                    testTryParse(formatter, "12:34:56:78:90:ab::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0))),
                    testTryParse(formatter, "12:34:56:78:90::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0))),
                    testTryParse(formatter, "12:34:56:78::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0))),
                    testTryParse(formatter, "12:34:56::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0))),
                    testTryParse(formatter, "12:34::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0))),
                    testTryParse(formatter, "12::", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0))),

                    testTryParse(formatter, "12:34:56:78:90:ab::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56:78:90::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56:78::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12::ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "::ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF))),

                    testTryParse(formatter, "12:34:56:78:90::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56:78::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "::cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56:78:90::192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56:78::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34:56:78::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56:78::ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34:56::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56::90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34::78:90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12::56:78:90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::56:78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

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
        public DynamicTest[] testParseToBytes() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseToBytesWithPosition() {
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
        public DynamicTest[] testTryParseToBytes() {
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

        @TestFactory
        public DynamicTest[] testIsValid() {
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
        public DynamicTest[] testTestIfValid() {
            IPAddressFormatter<IPv6Address> formatter = IPAddressFormatter.ipv6WithDefaults();
            return new DynamicTest[] {
                    testTestIfValid(formatter, null, null),
                    testTestIfValid(formatter, "", null),

                    testTestIfValid(formatter, "::1", IPv6Address.LOCALHOST),
                    testTestIfValid(formatter, "::", IPv6Address.MIN_VALUE),
                    testTestIfValid(formatter, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPv6Address.MAX_VALUE),

                    testTestIfValid(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
                    testTestIfValid(formatter, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

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

        @TestFactory
        public DynamicTest[] testToString() {
            return new DynamicTest[] {
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.ipv6()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#IPv6[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
            };
        }

        private DynamicTest testToString(Builder<IPv6Address> builder, String expectedPostfix) {
            IPAddressFormatter<IPv6Address> formatter = builder.build();
            return dynamicTest(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), () -> {
                assertEquals(IPAddressFormatter.class.getName() + expectedPostfix, formatter.toString());
            });
        }
    }

    @Nested
    public class AnyVersion {

        @TestFactory
        public DynamicContainer[] testFormatIPAddress() {
            return testFormat(Function.identity(), new Formatters<>(IPAddressFormatter::format, IPAddressFormatter::format),
                    formatter -> dynamicTest("unsupported IP address", () -> {
                        IllegalStateException exception;
                        exception = assertThrows(IllegalStateException.class, () -> formatter.format(new TestIPAddress()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                        exception = assertThrows(IllegalStateException.class, () -> formatter.format(new TestIPAddress(), new StringBuilder()));
                        assertEquals("unsupported IP addres type: " + TestIPAddress.class, exception.getMessage());
                    }));
        }

        @TestFactory
        public DynamicContainer[] testFormatBytes() {
            return testFormat(IPAddress::toByteArray, new Formatters<IPAddress<?>, byte[]>(IPAddressFormatter::format, IPAddressFormatter::format),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 0),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 15),
                    formatter -> testFormatBytesOfInvalidLength(formatter, 17));
        }

        @SafeVarargs
        private final <T> DynamicContainer[] testFormat(Function<IPAddress<?>, T> mapper,
                Formatters<IPAddress<?>, T> formatters,
                Function<IPAddressFormatter<IPAddress<?>>, DynamicTest>... additionalTests) {

            return new DynamicContainer[] {
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::", "::1", "1::", "123:456:789:100:abcd:ef00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:abcd:ef00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::", "::1", "1::", "123:456:789:100:ABCD:EF00:1000:1", "1200::1234:1:1", "1200::1234:0:0", "1200:0:0:1234:5678::",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::]", "[::1]", "[1::]", "[123:456:789:100:ABCD:EF00:1000:1]", "[1200::1234:1:1]", "[1200::1234:0:0]",
                            "[1200:0:0:1234:5678::]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "::0.0.0.0", "::0.0.0.1", "1::0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1", "1200::1234:0.1.0.1", "1200::1234:0.0.0.0",
                            "1200::1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[::0.0.0.0]", "[::0.0.0.1]", "[1::0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]", "[1200::1234:0.1.0.1]",
                            "[1200::1234:0.0.0.0]", "[1200::1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:abcd:ef00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:abcd:ef00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:abcd:ef00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:abcd:ef00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "123:456:789:100:ABCD:EF00:1000:1", "1200:0:0:0:0:1234:1:1",
                            "1200:0:0:0:0:1234:0:0", "1200:0:0:1234:5678:0:0:0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0:0]", "[0:0:0:0:0:0:0:1]", "[1:0:0:0:0:0:0:0]", "[123:456:789:100:ABCD:EF00:1000:1]",
                            "[1200:0:0:0:0:1234:1:1]", "[1200:0:0:0:0:1234:0:0]", "[1200:0:0:1234:5678:0:0:0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0:0:0:0:0:0:0.0.0.0", "0:0:0:0:0:0:0.0.0.1", "1:0:0:0:0:0:0.0.0.0", "123:456:789:100:ABCD:EF00:16.0.0.1",
                            "1200:0:0:0:0:1234:0.1.0.1", "1200:0:0:0:0:1234:0.0.0.0", "1200:0:0:1234:5678:0:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0:0:0:0:0:0:0.0.0.0]", "[0:0:0:0:0:0:0.0.0.1]", "[1:0:0:0:0:0:0.0.0.0]", "[123:456:789:100:ABCD:EF00:16.0.0.1]",
                            "[1200:0:0:0:0:1234:0.1.0.1]", "[1200:0:0:0:0:1234:0.0.0.0]", "[1200:0:0:1234:5678:0:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:abcd:ef00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:abcd:ef00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:abcd:ef00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:abcd:ef00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0001",
                            "0001:0000:0000:0000:0000:0000:0000:0000", "0123:0456:0789:0100:ABCD:EF00:1000:0001",
                            "1200:0000:0000:0000:0000:1234:0001:0001", "1200:0000:0000:0000:0000:1234:0000:0000",
                            "1200:0000:0000:1234:5678:0000:0000:0000",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0000:0000]", "[0000:0000:0000:0000:0000:0000:0000:0001]",
                            "[0001:0000:0000:0000:0000:0000:0000:0000]", "[0123:0456:0789:0100:ABCD:EF00:1000:0001]",
                            "[1200:0000:0000:0000:0000:1234:0001:0001]", "[1200:0000:0000:0000:0000:1234:0000:0000]",
                            "[1200:0000:0000:1234:5678:0000:0000:0000]",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), mapper, formatters,
                            "0000:0000:0000:0000:0000:0000:0.0.0.0", "0000:0000:0000:0000:0000:0000:0.0.0.1",
                            "0001:0000:0000:0000:0000:0000:0.0.0.0", "0123:0456:0789:0100:ABCD:EF00:16.0.0.1",
                            "1200:0000:0000:0000:0000:1234:0.1.0.1", "1200:0000:0000:0000:0000:1234:0.0.0.0",
                            "1200:0000:0000:1234:5678:0000:0.0.0.0",
                            additionalTests),
                    testFormat(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), mapper, formatters,
                            "[0000:0000:0000:0000:0000:0000:0.0.0.0]", "[0000:0000:0000:0000:0000:0000:0.0.0.1]",
                            "[0001:0000:0000:0000:0000:0000:0.0.0.0]", "[0123:0456:0789:0100:ABCD:EF00:16.0.0.1]",
                            "[1200:0000:0000:0000:0000:1234:0.1.0.1]", "[1200:0000:0000:0000:0000:1234:0.0.0.0]",
                            "[1200:0000:0000:1234:5678:0000:0.0.0.0]",
                            additionalTests),
            };
        }

        @SafeVarargs
        private final <T> DynamicContainer testFormat(Builder<IPAddress<?>> builder, Function<IPAddress<?>, T> mapper,
                Formatters<IPAddress<?>, T> formatters, String expected1,
                String expected2, String expected3, String expected4, String expected5, String expected6, String expected7,
                Function<IPAddressFormatter<IPAddress<?>>, DynamicTest>... additionalTests) {

            IPAddressFormatter<IPAddress<?>> formatter = builder.build();
            DynamicTest[] tests = {
                    dynamicTest("null", () -> formatters.testNull(formatter)),

                    testFormat(formatter, mapper, formatters, IPv4Address.LOCALHOST, "127.0.0.1"),
                    testFormat(formatter, mapper, formatters, IPv4Address.MIN_VALUE, "0.0.0.0"),
                    testFormat(formatter, mapper, formatters, IPv4Address.MAX_VALUE, "255.255.255.255"),
                    testFormat(formatter, mapper, formatters, IPv4Address.valueOf(123, 234, 210, 109), "123.234.210.109"),
                    testFormat(formatter, mapper, formatters, IPv4Address.valueOf(1, 2, 3, 4), "1.2.3.4"),

                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0L, 0L), expected1),
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0L, 1L), expected2),
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x0001000000000000L, 0L), expected3),
                    // no zeroes sections
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x0123045607890100L, 0xABCDEF0010000001L), expected4),
                    // one zeroes sections
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000000000L, 0x0000123400010001L), expected5),
                    // two zeroes sections, the first one being the longest
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000000000L, 0x0000123400000000L), expected6),
                    // two zeroes sections, the second one being the longest
                    testFormat(formatter, mapper, formatters, IPv6Address.valueOf(0x1200000000001234L, 0x5678000000000000L), expected7),
            };
            if (additionalTests.length > 0) {
                tests = Stream.concat(
                        Arrays.stream(tests),
                        Arrays.stream(additionalTests).map(f -> f.apply(formatter))
                ).toArray(DynamicTest[]::new);
            }
            return dynamicContainer(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), Arrays.asList(tests));
        }

        private <T> DynamicTest testFormat(IPAddressFormatter<IPAddress<?>> formatter, Function<IPAddress<?>, T> mapper,
                Formatters<IPAddress<?>, T> formatters, IPAddress<?> address, String expected) {

            return dynamicTest(address.toString(), () -> formatters.test(formatter, mapper.apply(address), expected));
        }

        private DynamicTest testFormatBytesOfInvalidLength(IPAddressFormatter<IPAddress<?>> formatter, int length) {
            return dynamicTest(String.format("invalid length: %d", length), () -> {
                IllegalArgumentException exception;
                exception = assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length]));
                assertEquals(Messages.IPAddress.invalidArraySize.get(length), exception.getMessage());
                assertThrows(IllegalArgumentException.class, () -> formatter.format(new byte[length], new StringBuilder()));
                assertEquals(Messages.IPAddress.invalidArraySize.get(length), exception.getMessage());
            });
        }

        // valueOf is tested through IPAddressTest.testValueOfCharSequence

        @TestFactory
        public DynamicTest[] testParse() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parse("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parse(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseWithPosition() {
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

                    testParseWithPosition(formatter, "12:34:56:78:90:ab:cd:ef", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF)),
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
        public DynamicTest[] testTryParse() {
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

                    testTryParse(formatter, "12:34:56:78:90:ab:cd::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0))),
                    testTryParse(formatter, "12:34:56:78:90:ab::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0))),
                    testTryParse(formatter, "12:34:56:78:90::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0))),
                    testTryParse(formatter, "12:34:56:78::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0))),
                    testTryParse(formatter, "12:34:56::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0))),
                    testTryParse(formatter, "12:34::", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0))),
                    testTryParse(formatter, "12::", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0))),

                    testTryParse(formatter, "12:34:56:78:90:ab::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56:78:90::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56:78::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34:56::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12:34::ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "12::ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0, 0xEF))),
                    testTryParse(formatter, "::ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0, 0xEF))),

                    testTryParse(formatter, "12:34:56:78:90::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56:78::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xCD, 0xEF))),
                    testTryParse(formatter, "::cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56:78:90::192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56:78::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34:56:78::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34:56::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56:78::ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34:56::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34:56::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12:34::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34:56::90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0x56, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12:34::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0, 0x90, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12:34::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "12::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12:34::78:90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0x34, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "12::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0x12, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

                    testTryParse(formatter, "12::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),
                    testTryParse(formatter, "::56:78:90:ab:cd:ef", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF))),

                    testTryParse(formatter, "12::56:78:90:ab:192.168.0.1",
                            Optional.of(IPv6Address.valueOf(0x12, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),
                    testTryParse(formatter, "::56:78:90:ab:192.168.0.1", Optional.of(IPv6Address.valueOf(0, 0, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1))),

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
        public DynamicTest[] testParseToBytes() {
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

                exception = assertThrows(ParseException.class, () -> formatter.parseToBytes("1" + source + "1", 1, 1 + source.length()));
                assertEquals(errorIndex + 1, exception.getErrorOffset());

                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, -1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, source.length() + 1));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, source.length() + 1, source.length()));
                assertThrows(IndexOutOfBoundsException.class, () -> formatter.parseToBytes(source, 0, -1));
            });
        }

        @TestFactory
        public DynamicTest[] testParseToBytesWithPosition() {
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
        public DynamicTest[] testTryParseToBytes() {
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

        @TestFactory
        public DynamicTest[] testIsValid() {
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
        public DynamicTest[] testTestIfValid() {
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
                    testTestIfValid(formatter, "12:34:56:78:90:ab:192.168.0.1", IPv6Address.valueOf(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xC0A8, 0x1)),

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

        @TestFactory
        public DynamicTest[] testToString() {
            return new DynamicTest[] {
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withShortStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=SHORT,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withMediumStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=MEDIUM,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toLowerCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=false,withIPv4End=true,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withoutIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=false,encloseInBrackets=true]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .notEnclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=false]"),
                    testToString(IPAddressFormatter.anyVersion()
                            .withLongStyle()
                            .toUpperCase()
                            .withIPv4End()
                            .enclosingInBrackets(), "#anyVersion[style=LONG,upperCase=true,withIPv4End=true,encloseInBrackets=true]"),
            };
        }

        private DynamicTest testToString(Builder<IPAddress<?>> builder, String expectedPostfix) {
            IPAddressFormatter<IPAddress<?>> formatter = builder.build();
            return dynamicTest(formatter.toString().replaceAll(".*\\[(.*)\\]", "$1"), () -> {
                assertEquals(IPAddressFormatter.class.getName() + expectedPostfix, formatter.toString());
            });
        }
    }

    private interface Formatter<IP extends IPAddress<?>, T> {

        String format(IPAddressFormatter<IP> formatter, T input);
    }

    private interface StringBuilderFormatter<IP extends IPAddress<?>, T> {

        StringBuilder format(IPAddressFormatter<IP> formatter, T input, StringBuilder sb);
    }

    private static final class Formatters<IP extends IPAddress<?>, T> {

        private final Formatter<IP, T> formatter;
        private final StringBuilderFormatter<IP, T> sbFormatter;

        private Formatters(Formatter<IP, T> formatter, StringBuilderFormatter<IP, T> sbFormatter) {
            this.formatter = formatter;
            this.sbFormatter = sbFormatter;
        }

        private void testNull(IPAddressFormatter<IP> addressFormatter) {
            assertThrows(NullPointerException.class, () -> formatter.format(addressFormatter, null));
            assertThrows(NullPointerException.class, () -> sbFormatter.format(addressFormatter, null, new StringBuilder()));
        }

        private void test(IPAddressFormatter<IP> addressFormatter, T input, String expected) {
            assertEquals(expected, formatter.format(addressFormatter, input));
            assertEquals(expected, sbFormatter.format(addressFormatter, input, new StringBuilder()).toString());
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
}
