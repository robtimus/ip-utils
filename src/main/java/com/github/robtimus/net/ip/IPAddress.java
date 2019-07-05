/*
 * IPAddress.java
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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Represents an IP address. Immutable.
 * <p>
 * Unlike {@link InetAddress}, this class is more lightweight and contains only the IP address itself, not host names.
 *
 * @author Rob Spoor
 * @param <IP> The IP address subclass.
 */
public abstract class IPAddress<IP extends IPAddress<IP>> implements Comparable<IP> {

    private String ipAddress;

    private InetAddress inetAddress;

    IPAddress() {
        this(null);
    }

    IPAddress(InetAddress inetAddress) {
        this.inetAddress = inetAddress;
    }

    /**
     * Returns the number of bits required to store the IP address.
     *
     * @return The number of bits required to store the IP address.
     */
    public abstract int bits();

    /**
     * Returns a byte array representation of this IP address. Its size is equal to {@link #bits()} divided by {@link Byte#SIZE}.
     * Furthermore, the result is in network byte order; the highest order byte is in the first element.
     *
     * @return A byte array representation of this IP address.
     */
    public abstract byte[] toByteArray();

    /**
     * Returns this IP address as an {@link InetAddress}.
     *
     * @return This IP address as an {@link InetAddress}.
     */
    public InetAddress toInetAddress() {
        if (inetAddress == null) {
            byte[] address = toByteArray();
            try {
                inetAddress = InetAddress.getByAddress(address);
            } catch (UnknownHostException e) {
                // should not occur
                throw new IllegalStateException(e);
            }
        }
        return inetAddress;
    }

    /**
     * Tests whether or not another object is equal to this IP address.
     * An object is equal if it is a IP address with an equal return value of {@link #toByteArray()}.
     * <p>
     * Implementations do not necessary need to use {@link #toByteArray()}, as long as equal IP addresses also have equal byte array representations.
     */
    @Override
    public abstract boolean equals(Object o);

    /**
     * Returns a hash code value for this IP address.
     * <p>
     * Implementations do not necessarily need to use {@link #toByteArray()}, as long as the general contract as specified by
     * {@link Object#hashCode()} is not violated.
     */
    @Override
    public abstract int hashCode();

    /**
     * Returns a string representation of this IP address.
     * When this string representation is used with {@link IPAddressFormatter#parse(CharSequence)}, the resulting IP address should be equal to this
     * IP address.
     */
    @Override
    public String toString() {
        if (ipAddress == null) {
            ipAddress = format();
        }
        return ipAddress;
    }

    abstract String format();

    /**
     * Returns whether or not this IP address is an IP multicast address.
     *
     * @return {@code true} if this IP address is an IP multicast address, or {@code false} otherwise.
     * @see InetAddress#isMulticastAddress()
     */
    public abstract boolean isMulticastAddress();

    /**
     * Returns whether or not this IP address is a wildcard address.
     *
     * @return {@code true} if this IP address is a wildcard address, or {@code false} otherwise.
     * @see InetAddress#isAnyLocalAddress()
     */
    public abstract boolean isWildcardAddress();

    /**
     * Returns whether or not this IP address is a loopback address.
     *
     * @return {@code true} if this IP address is a loopback address, or {@code false} otherwise.
     * @see InetAddress#isLoopbackAddress()
     */
    public abstract boolean isLoopbackAddress();

    /**
     * Returns whether or not this IP address is a link local address.
     *
     * @return {@code true} if this IP address is a link local address, or {@code false} otherwise.
     * @see InetAddress#isLinkLocalAddress()
     */
    public abstract boolean isLinkLocalAddress();

    /**
     * Returns whether or not this IP address is a site local address.
     *
     * @return {@code true} if this IP address is a site local address, or {@code false} otherwise.
     * @see InetAddress#isSiteLocalAddress()
     */
    public abstract boolean isSiteLocalAddress();

    /**
     * Returns whether or not there is a next IP address.
     *
     * @return {@code true} if there is a next IP address, or {@code false} otherwise.
     */
    public abstract boolean hasNext();

    /**
     * Returns the next IP address if it exists.
     *
     * @return The next IP address.
     * @throws NoSuchElementException If there is no next IP address.
     * @see #hasNext()
     */
    public abstract IP next();

    /**
     * Returns whether or not there is a previous IP address.
     *
     * @return {@code true} if there is a previous IP address, or {@code false} otherwise.
     */
    public abstract boolean hasPrevious();

    /**
     * Returns the previous IP address if it exists.
     *
     * @return The previous IP address.
     * @throws NoSuchElementException If there is no previous IP address.
     * @see #hasPrevious()
     */
    public abstract IP previous();

    /**
     * Returns an IP range starting at this IP address and ending in another IP address.
     *
     * @param end The end of the IP range, inclusive.
     * @return An IP range from this IP address to the given IP address.
     * @throws NullPointerException If the given IP address is {@code null}.
     * @throws IllegalArgumentException If the given IP address is smaller than this IP address.
     */
    public abstract IPRange<IP> to(IP end);

    /**
     * Returns an IP range containing only this IP address.
     *
     * @return An IP range containing only this IP address.
     */
    public abstract IPRange<IP> asRange();

    /**
     * Returns a subnet of a specific prefix length that contains this IP address.
     *
     * @param prefixLength The prefix length of the subnet to return.
     * @return A subnet of the given prefix length that contains this IP address.
     * @throws IllegalArgumentException If the prefix length is negative or larger than {@link #bits()}.
     */
    public abstract Subnet<IP> inSubnet(int prefixLength);

    abstract Subnet<IP> startingSubnet(int prefixLength);

    abstract boolean isValidRoutingPrefix(int prefixLength);

    /**
     * Returns an IP address from a byte array representation of the address.
     *
     * @param address The array to return an IP address for.
     * @return An IP address that represents the given array.
     * @throws NullPointerException If the given array is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is not {@code 4} or {@code 16}.
     */
    public static IPAddress<?> valueOf(byte[] address) {
        switch (address.length) {
        case IPv4Address.BYTES:
            return IPv4Address.valueOf(address);
        case IPv6Address.BYTES:
            return IPv6Address.valueOf(address);
        default:
            throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
        }
    }

    /**
     * Returns an IP address represented by a {@code CharSequence}.
     *
     * @param address The IP address as a {@code CharSequence}.
     * @return An IP address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IP address.
     */
    public static IPAddress<?> valueOf(CharSequence address) {
        return valueOf(address, 0, address.length());
    }

    /**
     * Returns an IP address represented by a portion of a {@code CharSequence}.
     *
     * @param address The IP address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IP address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IP address ends, exclusive.
     * @return An IP address that represents the given address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws IllegalArgumentException If the given {@code CharSequence} does not represent a valid IP address.
     * @since 1.1
     */
    public static IPAddress<?> valueOf(CharSequence address, int start, int end) {
        return IPAddressFormatter.anyVersionWithDefaults().valueOf(address, start, end);
    }

    /**
     * Attempts to return an IP address represented by a {@code CharSequence}.
     *
     * @param address The possible IP address as a {@code CharSequence}.
     * @return An {@link Optional} with the IP address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IP address.
     */
    public static Optional<IPAddress<?>> tryValueOf(CharSequence address) {
        return address == null ? Optional.empty() : tryValueOf(address, 0, address.length());
    }

    /**
     * Attempts to return an IP address represented by a portion of a {@code CharSequence}.
     *
     * @param address The possible IP address as a {@code CharSequence}.
     * @param start The index in the {@code CharSequence} where the IP address starts, inclusive.
     * @param end The index in the {@code CharSequence} where the IP address ends, exclusive.
     * @return An {@link Optional} with the IP address that represents the given address, or {@link Optional#empty()} if the given
     *         {@code CharSequence} is {@code null}or does not represent a valid IP address.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static Optional<IPAddress<?>> tryValueOf(CharSequence address, int start, int end) {
        return IPAddressFormatter.anyVersionWithDefaults().tryParse(address, start, end);
    }

    /**
     * Returns an IP address represented by a {@code InetAddress}.
     *
     * @param address The IP address as a {@code InetAddress}.
     * @return An IP address that represents the given address.
     * @throws NullPointerException If the given {@code InetAddress} is {@code null}.
     * @throws IllegalArgumentException If the given {@link InetAddress} is not supported.
     */
    public static IPAddress<?> valueOf(InetAddress address) {
        if (address instanceof Inet4Address) {
            return IPv4Address.valueOf((Inet4Address) address);
        }
        if (address instanceof Inet6Address) {
            return IPv6Address.valueOf((Inet6Address) address);
        }
        // this should not occur, but let's call valueOf anyway to get a proper error message
        return valueOf(address.getAddress());
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid IP address.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the {@code CharSequence} is a valid IP address, or {@code false} otherwise.
     */
    public static boolean isIPAddress(CharSequence s) {
        return s != null && isIPAddress(s, 0, s.length());
    }

    /**
     * Tests whether or not a portion of a {@code CharSequence} is a valid IP address.
     *
     * @param s The {@code CharSequence} to test.
     * @param start The index in the {@code CharSequence} to start checking at, inclusive.
     * @param end The index in the {@code CharSequence} to end checking at, exclusive.
     * @return {@code true} if the {@code CharSequence} is a valid IP address, or {@code false} otherwise.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static boolean isIPAddress(CharSequence s, int start, int end) {
        return IPAddressFormatter.anyVersionWithDefaults().isValid(s, start, end);
    }

    /**
     * Returns a predicate that checks whether or not {@code CharSequence}s are valid IP addresses that match a specific predicate.
     * This predicate can handle {@code null} values, which do not match the predicate.
     *
     * @param predicate The predicate to check if {@code CharSequence}s are valid IP addresses.
     * @return A predicate that checks whether or not {@code CharSequence}s are valid IP addresses that match the given predicate.
     * @see #isIPAddress(CharSequence)
     */
    public static Predicate<CharSequence> ifValidIPAddress(Predicate<? super IPAddress<?>> predicate) {
        Objects.requireNonNull(predicate);
        return s -> s != null && IPAddressFormatter.anyVersionWithDefaults().testIfValid(s, predicate);
    }
}
