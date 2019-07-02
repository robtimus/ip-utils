/*
 * IPv6Address.java
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

import static com.github.robtimus.net.ip.Bytes.HSHIFT0;
import static com.github.robtimus.net.ip.Bytes.HSHIFT1;
import static com.github.robtimus.net.ip.Bytes.HSHIFT2;
import static com.github.robtimus.net.ip.Bytes.HSHIFT3;
import static com.github.robtimus.net.ip.Bytes.addressToHighAddress;
import static com.github.robtimus.net.ip.Bytes.addressToLowAddress;
import static com.github.robtimus.net.ip.Bytes.longsToAddress;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Represents an IPv6 address. Immutable.
 *
 * @author Rob Spoor
 */
public final class IPv6Address extends IPAddress<IPv6Address> {

    private static final BigInteger TWO = BigInteger.valueOf(2L);

    static final long LOCALHOST_HIGH_ADDRESS = 0L;
    static final long LOCALHOST_LOW_ADDRESS = 1L;
    static final long MIN_HIGH_ADDRESS = 0L;
    static final long MIN_LOW_ADDRESS = 0L;
    static final long MAX_HIGH_ADDRESS = 0xFFFF_FFFF_FFFF_FFFFL;
    static final long MAX_LOW_ADDRESS = 0xFFFF_FFFF_FFFF_FFFFL;

    static final int BITS = 2 * Long.SIZE;
    static final int BYTES = 2 * Long.BYTES;

    // each hextet is 2 bytes
    static final int HEXTETS = BITS / (2 * Byte.SIZE);

    private static final IPv6Address[] NETMASKS = new IPv6Address[BITS + 1];

    static {
        long netmask = 0xFFFF_FFFF_FFFF_FFFFL;
        long oneBits = 0xFFFF_FFFF_FFFF_FFFFL;
        int index = BITS;
        while (oneBits != 0) {
            NETMASKS[index--] = new IPv6Address(MAX_HIGH_ADDRESS, netmask & oneBits);
            oneBits <<= 1L;
        }
        oneBits = 0xFFFF_FFFF_FFFF_FFFFL;
        while (oneBits != 0) {
            NETMASKS[index--] = new IPv6Address(netmask & oneBits, MIN_LOW_ADDRESS);
            oneBits <<= 1L;
        }
        NETMASKS[index] = new IPv6Address(MIN_HIGH_ADDRESS, MIN_LOW_ADDRESS);
    }

    /** An IPv6 address object for localhost, {@code ::1}. */
    public static final IPv6Address LOCALHOST = new IPv6Address(LOCALHOST_HIGH_ADDRESS, LOCALHOST_LOW_ADDRESS);

    /** The minimum IPv6 address object, {@code ::}. */
    public static final IPv6Address MIN_VALUE = NETMASKS[0];

    /** The maximum IPv6 address object, {@code ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff}. */
    public static final IPv6Address MAX_VALUE = NETMASKS[BITS];

    final long highAddress;
    final long lowAddress;

    private BigInteger fullAddress = null;

    IPv6Address(long highAddress, long lowAddress) {
        this.highAddress = highAddress;
        this.lowAddress = lowAddress;
    }

    private IPv6Address(long highAddress, long lowAddress, Inet6Address inetAddress) {
        super(inetAddress);
        this.highAddress = highAddress;
        this.lowAddress = lowAddress;
    }

    /**
     * Returns the number of bits required to store the IP address, always {@code 128}.
     */
    @Override
    public int bits() {
        return BITS;
    }

    @Override
    public byte[] toByteArray() {
        return longsToAddress(highAddress, lowAddress);
    }

    /**
     * Returns an IPv4 representation of this IPv6 address if it is an IPv4 mapped address.
     * This IPv4 address is equivalent to {@code d.d.d.d} if this IPv6 address is {@code ::ffff:d.d.d.d}.
     *
     * @return An IPv4 representation of this IPv6 address.
     * @throws IllegalStateException If this IPv6 address is not an IPv4 mapped address.
     * @see #isIPv4Mapped()
     */
    public IPv4Address toIPv4() {
        if (isIPv4Mapped()) {
            return IPv4Address.valueOf((int) (lowAddress & 0x0000_0000_FFFF_FFFFL));
        }
        throw new IllegalStateException(Messages.IPv6Address.notIPv4Mapped.get(this));
    }

    /**
     * Returns whether or not this IPv6 address is an IPv4 mapped address.
     * An IPv6 address is an IPv4 mapped address if it's in the {@code ::ffff:0:0/96} subnet (from {@code ::ffff:0:0} to {@code ::ffff:ffff:ffff}).
     *
     * @return {@code true} if this IPv6 address is an IPv4 mapped address, or {@code false} otherwise.
     */
    public boolean isIPv4Mapped() {
        return highAddress == 0L && (lowAddress & 0xFFFF_FFFF_0000_0000L) == 0x0000_FFFF_0000_0000L;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        IPv6Address other = (IPv6Address) o;
        return highAddress == other.highAddress && lowAddress == other.lowAddress;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(highAddress) ^ Long.hashCode(lowAddress);
    }

    @Override
    String format() {
        return IPAddressFormatter.ipv6WithDefaults().format(this);
    }

    @Override
    public int compareTo(IPv6Address other) {
        int diff = Long.compareUnsigned(highAddress, other.highAddress);
        if (diff == 0) {
            diff = Long.compareUnsigned(lowAddress, other.lowAddress);
        }
        return diff;
    }

    /**
     * Returns whether or not this IP address is an IP multicast address.
     * This method returns whether or not the IP address is in subnet {@code ff00::/8}.
     *
     * @return {@code true} if this IP address is an IP multicast address, or {@code false} otherwise.
     * @see Inet6Address#isMulticastAddress()
     */
    @Override
    public boolean isMulticastAddress() {
        return (highAddress & 0xFF00_0000_0000_0000L) == 0xFF00_0000_0000_0000L;
    }

    /**
     * Returns whether or not this IP address is a wildcard address.
     *
     * @return {@code true} if this IP address is a wildcard address, or {@code false} otherwise.
     * @see Inet6Address#isAnyLocalAddress()
     */
    @Override
    public boolean isWildcardAddress() {
        return highAddress == MIN_HIGH_ADDRESS && lowAddress == MIN_LOW_ADDRESS;
    }

    /**
     * Returns whether or not this IP address is a loopback address.
     *
     * @return {@code true} if this IP address is a loopback address, or {@code false} otherwise.
     * @see Inet6Address#isLoopbackAddress()
     */
    @Override
    public boolean isLoopbackAddress() {
        return highAddress == LOCALHOST_HIGH_ADDRESS && lowAddress == LOCALHOST_LOW_ADDRESS;
    }

    /**
     * Returns whether or not this IP address is a link local address.
     * This method returns whether or not the IP address is in the {@code fe80::/10} subnet.
     *
     * @return {@code true} if this IP address is a link local address, or {@code false} otherwise.
     * @see Inet6Address#isLinkLocalAddress()
     */
    @Override
    public boolean isLinkLocalAddress() {
        return (highAddress & 0xFFC0_0000_0000_0000L) == 0xFE80_0000_0000_0000L;
    }

    /**
     * Returns whether or not this IP address is a site local address.
     * This method returns whether or not the IP address is in the {@code fec0::/10} subnets.
     *
     * @return {@code true} if this IP address is a site local address, or {@code false} otherwise.
     * @see Inet6Address#isSiteLocalAddress()
     */
    @Override
    public boolean isSiteLocalAddress() {
        return (highAddress & 0xFFC0_0000_0000_0000L) == 0xFEC0_0000_0000_0000L;
    }

    @Override
    public boolean hasNext() {
        return highAddress != MAX_HIGH_ADDRESS || lowAddress != MAX_LOW_ADDRESS;
    }

    @Override
    public IPv6Address next() {
        if (lowAddress != MAX_LOW_ADDRESS) {
            return valueOf(highAddress, lowAddress + 1);
        }
        if (highAddress != MAX_HIGH_ADDRESS) {
            return valueOf(highAddress + 1, MIN_LOW_ADDRESS);
        }
        throw new NoSuchElementException();
    }

    @Override
    public boolean hasPrevious() {
        return highAddress != MIN_HIGH_ADDRESS || lowAddress != MIN_LOW_ADDRESS;
    }

    @Override
    public IPv6Address previous() {
        if (lowAddress != MIN_LOW_ADDRESS) {
            return valueOf(highAddress, lowAddress - 1);
        }
        if (highAddress != MIN_HIGH_ADDRESS) {
            return valueOf(highAddress - 1, MAX_LOW_ADDRESS);
        }
        throw new NoSuchElementException();
    }

    IPv6Address mid(IPv6Address high) {
        BigInteger midAddress = address().add(high.address()).divide(TWO);
        long midHighAddress = addressToHighAddress(midAddress);
        long midLowAddress = addressToLowAddress(midAddress);
        if (midHighAddress == highAddress && midLowAddress == lowAddress) {
            return this;
        }
        if (midHighAddress == high.highAddress && midLowAddress == high.lowAddress) {
            return high;
        }
        IPv6Address mid = valueOf(midHighAddress, midLowAddress);
        mid.fullAddress = midAddress;
        return mid;
    }

    private BigInteger address() {
        if (fullAddress == null) {
            fullAddress = new BigInteger(1, toByteArray());
        }
        return fullAddress;
    }

    @Override
    public IPv6Range to(IPv6Address end) {
        if (this.compareTo(end) > 0) {
            throw new IllegalArgumentException(Messages.IPRange.toSmallerThanFrom.get(end, this));
        }
        return this.equals(end) ? asRange() : new IPRangeImpl.IPv6(this, end);
    }

    @Override
    public IPv6Range asRange() {
        return new SingletonIPRange.IPv6(this);
    }

    @Override
    public IPv6Subnet inSubnet(int prefixLength) {
        return inSubnet(prefixLength, false);
    }

    @Override
    IPv6Subnet startingSubnet(int prefixLength) {
        return inSubnet(prefixLength, true);
    }

    private IPv6Subnet inSubnet(int prefixLength, boolean mustStart) {
        IPv6Address netmask = getNetmask(prefixLength);
        IPv6Address routingPrefix = this;
        long routingPrefixHighAddress = highAddress & netmask.highAddress;
        long routingPrefixLowAddress = lowAddress & netmask.lowAddress;
        if (highAddress != routingPrefixHighAddress || lowAddress != routingPrefixLowAddress) {
            if (mustStart) {
                throw new IllegalArgumentException(Messages.Subnet.invalidRoutingPrefix.get(this, prefixLength));
            }
            routingPrefix = valueOf(routingPrefixHighAddress, routingPrefixLowAddress);
        }
        long toHighAddress = highAddress | ~netmask.highAddress;
        long toLowAddress = lowAddress | ~netmask.lowAddress;
        IPv6Address to = highAddress == toHighAddress && lowAddress == toLowAddress ? this : valueOf(toHighAddress, toLowAddress);
        return new IPv6Subnet(routingPrefix, to, prefixLength);
    }

    @Override
    boolean isValidRoutingPrefix(int prefixLength) {
        IPv6Address netmask = getNetmask(prefixLength);
        long routingPrefixHighAddress = highAddress & netmask.highAddress;
        long routingPrefixLowAddress = lowAddress & netmask.lowAddress;
        return highAddress == routingPrefixHighAddress && lowAddress == routingPrefixLowAddress;
    }

    static IPv6Address valueOf(long highAddress, long lowAddress) {
        if (highAddress == LOCALHOST_HIGH_ADDRESS && lowAddress == LOCALHOST_LOW_ADDRESS) {
            return LOCALHOST;
        }
        if (highAddress == MIN_HIGH_ADDRESS && lowAddress == MIN_LOW_ADDRESS) {
            return MIN_VALUE;
        }
        if (highAddress == MAX_HIGH_ADDRESS && lowAddress == MAX_LOW_ADDRESS) {
            return MAX_VALUE;
        }
        for (IPv6Address netmask : NETMASKS) {
            if (netmask.highAddress == highAddress && netmask.lowAddress == lowAddress) {
                return netmask;
            }
        }
        return new IPv6Address(highAddress, lowAddress);
    }

    /**
     * Returns an IPv6 address from eight hextets.
     * For example, {@code valueOf(0xFF, 0xAB, 0, 0, 0, 0, 0, 1)} will return an IPv6 address that represents {@code ff:ab::1}.
     *
     * @param hextet1 The first hextet.
     * @param hextet2 The second hextet.
     * @param hextet3 The third hextet.
     * @param hextet4 The fourth hextet.
     * @param hextet5 The fifth hextet.
     * @param hextet6 The sixth hextet.
     * @param hextet7 The seventh hextet.
     * @param hextet8 The eighth hextet.
     * @return An IPv6 address that represents the given hextets.
     * @throws IllegalArgumentException If any of the octets is not between 0 and 0xFFFF, inclusive.
     */
    public static IPv6Address valueOf(int hextet1, int hextet2, int hextet3, int hextet4, int hextet5, int hextet6, int hextet7, int hextet8) {
        validateHextet(hextet1);
        validateHextet(hextet2);
        validateHextet(hextet3);
        validateHextet(hextet4);
        validateHextet(hextet5);
        validateHextet(hextet6);
        validateHextet(hextet7);
        validateHextet(hextet8);

        long highAddress = ((long) hextet1 << HSHIFT3) | ((long) hextet2 << HSHIFT2) | ((long) hextet3 << HSHIFT1) | ((long) hextet4 << HSHIFT0);
        long lowAddress = ((long) hextet5 << HSHIFT3) | ((long) hextet6 << HSHIFT2) | ((long) hextet7 << HSHIFT1) | ((long) hextet8 << HSHIFT0);
        return valueOf(highAddress, lowAddress);
    }

    private static void validateHextet(int hextet) {
        if (hextet < 0 || hextet > 0xFFFF) {
            throw new IllegalArgumentException(Messages.IPv6Address.invalidHextet.get(hextet));
        }
    }

    /**
     * Returns an IPv6 address from a byte array representation of the address.
     *
     * @param address The array to return an IPv6 address for.
     * @return An IPv6 address that represents the given array.
     * @throws NullPointerException If the given array is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is not {@code 16}.
     */
    public static IPv6Address valueOf(byte[] address) {
        if (address.length != BYTES) {
            throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
        }

        long highAddress = addressToHighAddress(address);
        long lowAddress = addressToLowAddress(address);
        return valueOf(highAddress, lowAddress);
    }

    /**
     * Returns an IPv6 address represented by a {@code CharSequence}.
     *
     * @param address The IPv6 address as a {@code CharSequence}.
     * @return An IPv6 address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IPv6 address.
     */
    public static IPv6Address valueOf(CharSequence address) {
        return valueOf(address, 0, address.length());
    }

    /**
     * Returns an IPv6 address represented by a portion of a {@code CharSequence}.
     *
     * @param address The IPv6 address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IPv6 address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IPv6 address ends, exclusive.
     * @return An IPv6 address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IPv6 address.
     * @since 1.1
     */
    public static IPv6Address valueOf(CharSequence address, int start, int end) {
        return IPAddressFormatter.ipv6WithDefaults().valueOf(address, start, end);
    }

    /**
     * Attempts to return an IPv6 address represented by a {@code CharSequence}.
     *
     * @param address The possible IPv6 address as a {@code CharSequence}.
     * @return An {@link Optional} with the IPv6 address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IPv6 address.
     */
    public static Optional<IPv6Address> tryValueOfIPv6(CharSequence address) {
        return address == null ? Optional.empty() : tryValueOfIPv6(address, 0, address.length());
    }

    /**
     * Attempts to return an IPv6 address represented by a portion of a {@code CharSequence}.
     *
     * @param address The possible IPv6 address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IPv6 address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IPv6 address ends, exclusive.
     * @return An {@link Optional} with the IPv6 address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IPv6 address.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static Optional<IPv6Address> tryValueOfIPv6(CharSequence address, int start, int end) {
        return IPAddressFormatter.ipv6WithDefaults().tryParse(address, start, end);
    }

    /**
     * Returns an IPv6 address represented by a {@code Inet6Address}.
     *
     * @param address The IPv6 address as a {@code Inet6Address}.
     * @return An IPv6 address that represents the given address.
     * @throws NullPointerException If the given {@code Inet6Address} is {@code null}.
     */
    public static IPv6Address valueOf(Inet6Address address) {
        byte[] octets = address.getAddress();
        long highAddress = addressToHighAddress(octets);
        long lowAddress = addressToLowAddress(octets);
        return new IPv6Address(highAddress, lowAddress, address);
    }

    static IPv6Address getNetmask(int prefixLength) {
        if (prefixLength < 0 || prefixLength > BITS) {
            throw new IllegalArgumentException(Messages.IPAddress.invalidPrefixLength.get(prefixLength, BITS));
        }
        return NETMASKS[prefixLength];
    }

    boolean isValidNetmask() {
        for (IPv6Address netmask : NETMASKS) {
            if (netmask.highAddress == highAddress && netmask.lowAddress == lowAddress) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid IPv6 address.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the given {@code CharSequence} is a valid IPv6 address, or {@code false} otherwise.
     */
    public static boolean isIPv6Address(CharSequence s) {
        return s != null && isIPv6Address(s, 0, s.length());
    }

    /**
     * Tests whether or not a portion of a {@code CharSequence} is a valid IPv6 address.
     *
     * @param s The {@code CharSequence} to test.
     * @param start The index in the {@code CharSequence} to start checking at, inclusive.
     * @param end The index in the {@code CharSequence} to end checking at, exclusive.
     * @return {@code true} if the given {@code CharSequence} is a valid IPv6 address, or {@code false} otherwise.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static boolean isIPv6Address(CharSequence s, int start, int end) {
        return IPAddressFormatter.ipv6WithDefaults().isValid(s, start, end);
    }

    /**
     * Returns a predicate that checks whether or not {@code CharSequence}s are valid IPv6 addresses that match a specific predicate.
     * This predicate can handle {@code null} values, which do not match the predicate.
     *
     * @param predicate The predicate to check if {@code CharSequence}s are valid IP addresses.
     * @return A predicate that checks whether or not {@code CharSequence}s are valid IP addresses that match the given predicate.
     * @see #isIPv6Address(CharSequence)
     */
    public static Predicate<CharSequence> ifValidIPv6Address(Predicate<? super IPv6Address> predicate) {
        Objects.requireNonNull(predicate);
        return s -> s != null && IPAddressFormatter.ipv6WithDefaults().testIfValid(s, predicate);
    }
}
