/*
 * IPv4Address.java
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

import static com.github.robtimus.net.ip.Bytes.OSHIFT0;
import static com.github.robtimus.net.ip.Bytes.OSHIFT1;
import static com.github.robtimus.net.ip.Bytes.OSHIFT2;
import static com.github.robtimus.net.ip.Bytes.OSHIFT3;
import static com.github.robtimus.net.ip.Bytes.addressToInt;
import static com.github.robtimus.net.ip.Bytes.intToAddress;
import java.net.Inet4Address;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Represents an IPv4 address. Immutable.
 *
 * @author Rob Spoor
 */
public final class IPv4Address extends IPAddress<IPv4Address> {

    static final int LOCALHOST_ADDRESS = (127 << OSHIFT3) | 1;
    static final int MIN_ADDRESS = 0;
    static final int MAX_ADDRESS = 0xFFFF_FFFF;

    static final int BITS = Integer.SIZE;
    static final int BYTES = Integer.BYTES;

    // each octet is 1 byte
    static final int OCTETS = BITS / Byte.SIZE;

    private static final IPv4Address[] NETMASKS = new IPv4Address[BITS + 1];

    static {
        int netmask = 0xFFFF_FFFF;
        int oneBits = 0xFFFF_FFFF;
        for (int i = BITS; i >= 0; i--) {
            NETMASKS[i] = new IPv4Address(netmask & oneBits);
            oneBits <<= 1;
        }
    }

    /** An IPv4 address object for localhost, {@code 127.0.0.1}. */
    public static final IPv4Address LOCALHOST = new IPv4Address(LOCALHOST_ADDRESS);

    /** The minimum IPv4 address object, {@code 0.0.0.0}. */
    public static final IPv4Address MIN_VALUE = NETMASKS[0];

    /** The maximum IPv4 address object, {@code 255.255.255.255}. */
    public static final IPv4Address MAX_VALUE = NETMASKS[BITS];

    final int address;

    IPv4Address(int address) {
        this.address = address;
    }

    private IPv4Address(int address, Inet4Address inetAddress) {
        super(inetAddress);
        this.address = address;
    }

    /**
     * Returns the number of bits required to store the IP address, always {@code 32}.
     */
    @Override
    public int bits() {
        return BITS;
    }

    @Override
    public byte[] toByteArray() {
        return intToAddress(address);
    }

    /**
     * Returns an IPv6 representation of this IPv4 address.
     * This IPv6 address is equivalent to {@code ::ffff:d.d.d.d}, where {@code d.d.d.d} represents this IPv4 address.
     *
     * @return An IPv6 representation of this IPv4 address.
     */
    public IPv6Address toIPv6() {
        return IPv6Address.valueOf(0L, 0x0000_FFFF_0000_0000L | (address & 0x0000_0000_FFFF_FFFFL));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        IPv4Address other = (IPv4Address) o;
        return address == other.address;
    }

    @Override
    public int hashCode() {
        return address;
    }

    @Override
    String format() {
        return IPAddressFormatter.ipv4().format(this);
    }

    @Override
    public int compareTo(IPv4Address other) {
        return Integer.compareUnsigned(address, other.address);
    }

    /**
     * Returns whether or not this IP address is an IP multicast address.
     * An IP multicast address is a Class D address, which means the first four bits of the address are {@code 1110}.
     * In other words, this method returns whether or not the IP address is in range {@code 224.0.0.0} through {@code 239.255.255.255}.
     *
     * @return {@code true} if this IP address is an IP multicast address, or {@code false} otherwise.
     * @see Inet4Address#isMulticastAddress()
     */
    @Override
    public boolean isMulticastAddress() {
        // 0b1110 == 0xE
        return (address & 0xF000_0000) == 0xE000_0000;
    }

    /**
     * Returns whether or not this IP address is a wildcard address.
     *
     * @return {@code true} if this IP address is a wildcard address, or {@code false} otherwise.
     * @see Inet4Address#isAnyLocalAddress()
     */
    @Override
    public boolean isWildcardAddress() {
        return address == 0;
    }

    /**
     * Returns whether or not this IP address is a loopback address.
     * A loopback address is any address in the {@code 127.0.0.0/8} subnet.
     *
     * @return {@code true} if this IP address is a loopback address, or {@code false} otherwise.
     * @see Inet4Address#isLoopbackAddress()
     */
    @Override
    public boolean isLoopbackAddress() {
        // 127 (decimal) == 0x7F
        return (address & 0xFF00_0000) == 0x7F00_0000;
    }

    /**
     * Returns whether or not this IP address is a link local address.
     * This method returns whether or not the IP address is in the {@code 169.254.0.0/16} subnet.
     *
     * @return {@code true} if this IP address is a link local address, or {@code false} otherwise.
     * @see Inet4Address#isLinkLocalAddress()
     */
    @Override
    public boolean isLinkLocalAddress() {
        // 169 (decimal) == 0xA9, 254 (decimal) == 0xFE
        return (address & 0xFFFF_0000) == 0xA9FE_0000;
    }

    /**
     * Returns whether or not this IP address is a site local address.
     * This method returns whether or not the IP address is in the {@code 10.0.0.0/8}, {@code 172.16.0.0/12} or {@code 192.168.0.0/16} subnets.
     *
     * @return {@code true} if this IP address is a site local address, or {@code false} otherwise.
     * @see Inet4Address#isSiteLocalAddress()
     */
    @Override
    public boolean isSiteLocalAddress() {
        // 10 (decimal) == 0x0A
        // 172 (decimal) == 0xAC, plus 1 for the next 4 bytes
        // 192 (decimal) == 0xC0, 168 (decimal) == 0xA8
        return (address & 0xFF00_0000) == 0x0A00_0000
                || (address & 0xFFF0_0000) == 0xAC10_0000
                || (address & 0xFFFF_0000) == 0xC0A8_0000;
    }

    @Override
    public boolean hasNext() {
        return address != MAX_ADDRESS;
    }

    @Override
    public IPv4Address next() {
        if (address != MAX_ADDRESS) {
            return valueOf(address + 1);
        }
        throw new NoSuchElementException();
    }

    @Override
    public boolean hasPrevious() {
        return address != MIN_ADDRESS;
    }

    @Override
    public IPv4Address previous() {
        if (address != MIN_ADDRESS) {
            return valueOf(address - 1);
        }
        throw new NoSuchElementException();
    }

    IPv4Address mid(IPv4Address high) {
        int mid = Bytes.mid(address, high.address);
        return Integer.compareUnsigned(address, mid) >= 0 ? this : valueOf(mid);
    }

    @Override
    public IPv4Range to(IPv4Address end) {
        if (this.compareTo(end) > 0) {
            throw new IllegalArgumentException(Messages.IPRange.toSmallerThanFrom.get(end, this));
        }
        return this.equals(end) ? asRange() : new IPRangeImpl.IPv4(this, end);
    }

    @Override
    public IPv4Range asRange() {
        return new SingletonIPRange.IPv4(this);
    }

    @Override
    public IPv4Subnet inSubnet(int prefixLength) {
        return inSubnet(prefixLength, false);
    }

    @Override
    IPv4Subnet startingSubnet(int prefixLength) {
        return inSubnet(prefixLength, true);
    }

    IPv4Subnet startingSubnet(IPv4Address netmask) {
        int prefixLength = prefixLengthOfNetmask(netmask);
        if (prefixLength == -1) {
            throw new IllegalArgumentException(Messages.Subnet.invalidNetmask.get(netmask));
        }
        return inSubnet(netmask, prefixLength, true);
    }

    private IPv4Subnet inSubnet(int prefixLength, boolean mustStart) {
        IPv4Address netmask = getNetmask(prefixLength);
        return inSubnet(netmask, prefixLength, mustStart);
    }

    private IPv4Subnet inSubnet(IPv4Address netmask, int prefixLength, boolean mustStart) {
        IPv4Address routingPrefix = this;
        int routingPrefixAddress = address & netmask.address;
        if (address != routingPrefixAddress) {
            if (mustStart) {
                throw new IllegalArgumentException(Messages.Subnet.invalidRoutingPrefix.get(this, prefixLength));
            }
            routingPrefix = valueOf(routingPrefixAddress);
        }
        int toAddress = address | ~netmask.address;
        IPv4Address to = address == toAddress ? this : valueOf(toAddress);
        return new IPv4Subnet(routingPrefix, to, prefixLength);
    }

    @Override
    boolean isValidRoutingPrefix(int prefixLength) {
        IPv4Address netmask = getNetmask(prefixLength);
        int routingPrefixAddress = address & netmask.address;
        return address == routingPrefixAddress;
    }

    static IPv4Address valueOf(int address) {
        switch (address) {
            case LOCALHOST_ADDRESS:
                return LOCALHOST;
            case MIN_ADDRESS:
                return MIN_VALUE;
            case MAX_ADDRESS:
                return MAX_VALUE;
            default:
                for (IPv4Address netmask : NETMASKS) {
                    if (netmask.address == address) {
                        return netmask;
                    }
                }
                return new IPv4Address(address);
        }
    }

    /**
     * Returns an IPv4 address from four octets.
     * For example, {@code valueOf(192, 168, 0, 1)} will return an IPv4 address that represents {@code 192.168.0.1}.
     *
     * @param octet1 The first octet.
     * @param octet2 The second octet.
     * @param octet3 The third octet.
     * @param octet4 The fourth octet.
     * @return An IPv4 address that represents the given octets.
     * @throws IllegalArgumentException If any of the octets is not between 0 and 255, inclusive.
     */
    public static IPv4Address valueOf(int octet1, int octet2, int octet3, int octet4) {
        validateOctet(octet1);
        validateOctet(octet2);
        validateOctet(octet3);
        validateOctet(octet4);

        return valueOf((octet1 << OSHIFT3) | (octet2 << OSHIFT2) | (octet3 << OSHIFT1) | (octet4 << OSHIFT0));
    }

    private static void validateOctet(int octet) {
        if (octet < 0 || octet > 255) {
            throw new IllegalArgumentException(Messages.IPv4Address.invalidOctet.get(octet));
        }
    }

    /**
     * Returns an IPv4 address from a byte array representation of the address.
     *
     * @param address The array to return an IPv4 address for.
     * @return An IPv4 address that represents the given array.
     * @throws NullPointerException If the given array is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is not {@code 4}.
     */
    public static IPv4Address valueOf(byte[] address) {
        if (address.length != BYTES) {
            throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
        }

        return valueOf(addressToInt(address));
    }

    /**
     * Returns an IPv4 address represented by a {@code CharSequence}.
     *
     * @param address The IPv4 address as a {@code CharSequence}.
     * @return An IPv4 address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IPv4 address.
     */
    public static IPv4Address valueOf(CharSequence address) {
        return valueOf(address, 0, address.length());
    }

    /**
     * Returns an IPv4 address represented by a portion of a {@code CharSequence}.
     *
     * @param address The IPv4 address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IPv4 address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IPv4 address ends, exclusive.
     * @return An IPv4 address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IPv4 address.
     * @since 1.1
     */
    public static IPv4Address valueOf(CharSequence address, int start, int end) {
        return IPAddressFormatter.ipv4().valueOf(address, start, end);
    }

    /**
     * Attempts to return an IPv4 address represented by a {@code CharSequence}.
     *
     * @param address The possible IPv4 address as a {@code CharSequence}.
     * @return An {@link Optional} with the IPv4 address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IPv4 address.
     */
    public static Optional<IPv4Address> tryValueOfIPv4(CharSequence address) {
        return address == null ? Optional.empty() : tryValueOfIPv4(address, 0, address.length());
    }

    /**
     * Attempts to return an IPv4 address represented by a portion of a {@code CharSequence}.
     *
     * @param address The possible IPv4 address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IPv4 address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IPv4 address ends, exclusive.
     * @return An {@link Optional} with the IPv4 address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IPv4 address.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static Optional<IPv4Address> tryValueOfIPv4(CharSequence address, int start, int end) {
        return IPAddressFormatter.ipv4().tryParse(address, start, end);
    }

    /**
     * Returns an IPv4 address represented by a {@code Inet4Address}.
     *
     * @param address The IPv4 address as a {@code Inet4Address}.
     * @return An IPv4 address that represents the given address.
     * @throws NullPointerException If the given {@code Inet4Address} is {@code null}.
     */
    public static IPv4Address valueOf(Inet4Address address) {
        byte[] octets = address.getAddress();
        return new IPv4Address(addressToInt(octets), address);
    }

    /**
     * Returns an IPv4 address for a specific net mask.
     *
     * @param prefixLength The prefix length of the subnet for the net mask.
     *            For instance, {@code 0} represents a net mask for {@code /0} which is {@code 0.0.0.0},
     *            {@code 8} represents a net mask for a class A network {@code /8} which is {@code 255.0.0.0},
     *            {@code 16} represents a net mask for a class B network {@code /16} which is {@code 255.255.0.0},
     *            {@code 24} represents a net mask for a class C network {@code /24} which is {@code 255.255.255.0}, etc.
     * @return An IPv4 address representing a net mask with the given number of bits.
     * @throws IllegalArgumentException If the number of bits is not between {@code 0} and {@code 32}, inclusive.
     */
    public static IPv4Address getNetmask(int prefixLength) {
        if (prefixLength < 0 || prefixLength > BITS) {
            throw new IllegalArgumentException(Messages.IPAddress.invalidPrefixLength.get(prefixLength, BITS));
        }
        return NETMASKS[prefixLength];
    }

    /**
     * Returns whether or not this IPv4 address would be a valid netmask.
     * An IPv4 address would be a valid netmask if only its left-most bits are {@code 1}s.
     *
     * @return {@code true} if this IPv4 address would be a valid netmask, or {@code false} otherwise.
     */
    public boolean isValidNetmask() {
        return prefixLengthOfNetmask(this) != -1;
    }

    private int prefixLengthOfNetmask(IPv4Address address) {
        for (int i = 0; i < NETMASKS.length; i++) {
            if (NETMASKS[i].address == address.address) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid IPv4 address.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the {@code CharSequence} is a valid IP address, or {@code false} otherwise.
     */
    public static boolean isIPv4Address(CharSequence s) {
        return s != null && isIPv4Address(s, 0, s.length());
    }

    /**
     * Tests whether or not a portion of a {@code CharSequence} is a valid IPv4 address.
     *
     * @param s The {@code CharSequence} to test.
     * @param start The index in the {@code CharSequence} to start checking at, inclusive.
     * @param end The index in the {@code CharSequence} to end checking at, exclusive.
     * @return {@code true} if the {@code CharSequence} is a valid IP address, or {@code false} otherwise.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static boolean isIPv4Address(CharSequence s, int start, int end) {
        return IPAddressFormatter.ipv4().isValid(s, start, end);
    }

    /**
     * Returns a predicate that checks whether or not {@code CharSequence}s are valid IPv4 addresses that match a specific predicate.
     * This predicate can handle {@code null} values, which do not match the predicate.
     *
     * @param predicate The predicate to check if {@code CharSequence}s are valid IP addresses.
     * @return A predicate that checks whether or not {@code CharSequence}s are valid IP addresses that match the given predicate.
     * @see #isIPv4Address(CharSequence)
     */
    public static Predicate<CharSequence> ifValidIPv4Address(Predicate<? super IPv4Address> predicate) {
        Objects.requireNonNull(predicate);
        return s -> s != null && IPAddressFormatter.ipv4().testIfValid(s, predicate);
    }
}
