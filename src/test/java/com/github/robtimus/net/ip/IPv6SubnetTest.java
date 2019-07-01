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
import java.util.Optional;
import java.util.Spliterator;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class IPv6SubnetTest {

    @TestFactory
    public DynamicTest[] testSize() {
        return new DynamicTest[] {
                testSize(0, Integer.MAX_VALUE),
                testSize(8, Integer.MAX_VALUE),
                testSize(16, Integer.MAX_VALUE),
                testSize(24, Integer.MAX_VALUE),
                testSize(28, Integer.MAX_VALUE),
                testSize(32, Integer.MAX_VALUE),
                testSize(40, Integer.MAX_VALUE),
                testSize(48, Integer.MAX_VALUE),
                testSize(64, Integer.MAX_VALUE),
                testSize(72, Integer.MAX_VALUE),
                testSize(80, Integer.MAX_VALUE),
                testSize(88, Integer.MAX_VALUE),
                testSize(96, Integer.MAX_VALUE),
                testSize(97, Integer.MAX_VALUE),
                testSize(98, 1073741824),
                testSize(99, 536870912),
                testSize(100, 268435456),
                testSize(104, 16777216),
                testSize(112, 65536),
                testSize(120, 256),
                testSize(126, 4),
                testSize(127, 2),
                testSize(128, 1),
        };
    }

    private DynamicTest testSize(int prefixLength, int expectedSize) {
        IPv6Subnet subnet = IPv6Address.MIN_VALUE.startingSubnet(prefixLength);
        return dynamicTest(String.format("%s: %d", subnet, expectedSize), () -> {
            assertEquals(expectedSize, subnet.size());
            assertEquals(expectedSize, subnet.size());
        });
    }

    @Test
    public void testSpliterator() {
        IPv6Subnet subnet = IPv6Address.MIN_VALUE.startingSubnet(0);
        Spliterator<?> spliterator = subnet.spliterator();
        // IPv6RangeSpliterator has its own tests
        assertEquals(IPv6RangeSpliterator.class, spliterator.getClass());
    }

    @TestFactory
    public DynamicTest[] testValueOfCIDRNotation() {
        return new DynamicTest[] {
                dynamicTest("null", () -> assertThrows(NullPointerException.class, () -> IPv6Subnet.valueOf(null))),
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
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidFormat(CharSequence cidrNotation) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidCIDRNotation.get(cidrNotation), exception.getMessage());
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidRoutingPrefix(CharSequence cidrNotation, String routingPrefix, int prefixLength) {
        return dynamicTest(cidrNotation.toString(), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf(cidrNotation));
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(routingPrefix, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfCIDRNotationInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf("::1/" + prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testTryValueOfIPv6() {
        return new DynamicTest[] {
                testTryValueOfIPv6(null, Optional.empty()),
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
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv6Subnet.tryValueOfIPv6(cidrNotation)));
    }

    @TestFactory
    public DynamicTest[] testValueOfWithIPAddress() {
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
            assertEquals(Messages.Subnet.invalidRoutingPrefix.get(address, prefixLength), exception.getMessage());
        });
    }

    private DynamicTest testValueOfWithIPAddressInvalidPrefixLength(int prefixLength) {
        return dynamicTest(String.format("invalid prefix length: %d", prefixLength), () -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> IPv6Subnet.valueOf("::1", prefixLength));
            assertEquals(Messages.IPAddress.invalidPrefixLength.get(prefixLength, IPv6Address.BITS), exception.getMessage());
        });
    }

    @TestFactory
    public DynamicTest[] testIsIPv6Subnet() {
        return new DynamicTest[] {
                testIsIPv6Subnet(null, false),
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
        return dynamicTest(displayName.isEmpty() ? "empty" : displayName, () -> assertEquals(expected, IPv6Subnet.isIPv6Subnet(s)));
    }
}
