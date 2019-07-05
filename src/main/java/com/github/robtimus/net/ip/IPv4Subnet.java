/*
 * IPv4Subnet.java
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

import static com.github.robtimus.tryparse.TryParse.tryParseInt;
import java.util.Optional;
import java.util.Spliterator;

/**
 * Represents a subnet of IPv4 addresses. Immutable.
 *
 * @author Rob Spoor
 */
public final class IPv4Subnet extends Subnet<IPv4Address> implements IPv4Range {

    // Since only 2^31 - 1 is available, Integer.MAX_VALUE if (32 - routingPrefix) >= 31 or routingPrefix <= 32 - 31
    private static final int MIN_PREFIX_LENGTH_FOR_SIZE = IPv4Address.BITS - 31;

    private final int size;

    IPv4Subnet(IPv4Address from, IPv4Address to, int prefixLength) {
        super(from, to, prefixLength);
        size = prefixLength <= MIN_PREFIX_LENGTH_FOR_SIZE ? Integer.MAX_VALUE : 1 << (IPv4Address.BITS - prefixLength);
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public Spliterator<IPv4Address> spliterator() {
        return new IPv4RangeSpliterator(this);
    }

    /**
     * Returns an IPv4 subnet represented by a CIDR notation.
     *
     * @param cidrNotation The CIDR notation representing the IPv4 subnet.
     * @return An IPv4 subnet represented by the given CIDR notation.
     * @throws NullPointerException If the given CIDR notation is {@code null}.
     * @throws IllegalArgumentException If the given CIDR notation is invalid.
     */
    public static IPv4Subnet valueOf(CharSequence cidrNotation) {
        return valueOf(cidrNotation, 0, cidrNotation.length());
    }

    /**
     * Returns an IPv4 subnet represented by a CIDR notation.
     *
     * @param cidrNotation The CIDR notation representing the IPv4 subnet.
     * @param start The index in the {@code CharSequence} where the CIDR notation starts, inclusive.
     * @param end The index in the {@code CharSequence} where the CIDR notation ends, exclusive.
     * @return An IPv4 subnet represented by the given CIDR notation.
     * @throws NullPointerException If the given CIDR notation is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws IllegalArgumentException If the given CIDR notation is invalid.
     * @since 1.1
     */
    public static IPv4Subnet valueOf(CharSequence cidrNotation, int start, int end) {
        int index = indexOf(cidrNotation, '/', start, end);
        if (index == -1) {
            throw new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation));
        }
        IPv4Address routingPrefix = IPAddressFormatter.ipv4().tryParse(cidrNotation, start, index)
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        int prefixLength = tryParseInt(cidrNotation, index + 1, end)
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        return valueOf(routingPrefix, prefixLength);
    }

    /**
     * Attempts to return an IPv4 subnet represented by a {@code CharSequence}.
     *
     * @param cidrNotation The possible CIDR notation representing the IPv4 subnet.
     * @return An {@link Optional} with the IPv4 subnet represented by the given CIDR notation,
     *         or {@link Optional#empty()} if the given CIDR notation is {@code null} or invalid.
     */
    public static Optional<IPv4Subnet> tryValueOfIPv4(CharSequence cidrNotation) {
        return cidrNotation == null ? Optional.empty() : tryValueOfIPv4(cidrNotation, 0, cidrNotation.length());
    }

    /**
     * Attempts to return an IPv4 subnet represented by a portion of a {@code CharSequence}.
     *
     * @param cidrNotation The possible CIDR notation representing the IPv4 subnet.
     * @param start The index in the {@code CharSequence} where the CIDR notation starts, inclusive.
     * @param end The index in the {@code CharSequence} where the CIDR notation ends, exclusive.
     * @return An {@link Optional} with the IPv4 subnet represented by the given CIDR notation,
     *         or {@link Optional#empty()} if the given CIDR notation is {@code null} or invalid.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static Optional<IPv4Subnet> tryValueOfIPv4(CharSequence cidrNotation, int start, int end) {
        if (cidrNotation == null) {
            return Optional.empty();
        }
        int index = indexOf(cidrNotation, '/', start, end);
        if (index == -1) {
            return Optional.empty();
        }
        int prefixLength = tryParseInt(cidrNotation, index + 1, end).orElse(-1);
        if (0 <= prefixLength && prefixLength <= IPv4Address.BITS) {
            return IPAddressFormatter.ipv4().tryParse(cidrNotation, start, index)
                    .filter(ip -> ip.isValidRoutingPrefix(prefixLength))
                    .map(ip -> valueOf(ip, prefixLength));
        }
        return Optional.empty();
    }

    /**
     * Returns an IPv4 subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the IPv4 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv4 subnet.
     * @param prefixLength The length of the prefix of the IPv4 subnet.
     * @return An IPv4 subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the IPv4 subnet of the given prefix length that
     *                                      contains the routing prefix.
     */
    public static IPv4Subnet valueOf(IPv4Address routingPrefix, int prefixLength) {
        return routingPrefix.startingSubnet(prefixLength);
    }

    /**
     * Returns an IPv4 subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the IPv4 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv4 subnet.
     * @param prefixLength The length of the prefix of the IPv4 subnet.
     * @return An IPv4 subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given routing prefix does not represent a valid IP address,
     *                                      or if the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the IPv4 subnet of the given prefix length that
     *                                      contains the routing prefix.
     * @see #valueOf(IPv4Address, int)
     */
    public static IPv4Subnet valueOf(CharSequence routingPrefix, int prefixLength) {
        return valueOf(IPv4Address.valueOf(routingPrefix), prefixLength);
    }

    /**
     * Returns an IPv4 subnet represented by a routing prefix and a netmask.
     * The given routing prefix must be the start of the IPv4 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv4 subnet.
     * @param netmask The netmask of the IPv4 subnet.
     * @return An IPv4 subnet represented by the given routing prefix and netmask.
     * @throws NullPointerException If the given routing prefix or netmask is {@code null}.
     * @throws IllegalArgumentException If the given routing prefix or netmask does not represent a valid IP address,
     *                                      or if the given netmask is not a valid netmask,
     *                                      or if the given routing prefix is not the start of the IPv4 subnet of the given prefix length that
     *                                      contains the routing prefix.
     * @see IPv4Address#isValidNetmask()
     */
    public static IPv4Subnet valueOf(IPv4Address routingPrefix, IPv4Address netmask) {
        return routingPrefix.startingSubnet(netmask);
    }

    /**
     * Returns an IPv4 subnet represented by a routing prefix and a netmask.
     * The given routing prefix must be the start of the IPv4 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv4 subnet.
     * @param netmask The netmask of the IPv4 subnet.
     * @return An IPv4 subnet represented by the given routing prefix and netmask.
     * @throws NullPointerException If the given routing prefix or netmask is {@code null}.
     * @throws IllegalArgumentException If the given routing prefix or netmask does not represent a valid IP address,
     *                                      or if the given netmask is not a valid netmask,
     *                                      or if the given routing prefix is not the start of the IPv4 subnet of the given prefix length that
     *                                      contains the routing prefix.
     * @see #valueOf(IPv4Address, int)
     * @see IPv4Address#isValidNetmask()
     */
    public static IPv4Subnet valueOf(CharSequence routingPrefix, CharSequence netmask) {
        return valueOf(IPv4Address.valueOf(routingPrefix), IPv4Address.valueOf(netmask));
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid IPv4 subnet.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the {@code CharSequence} is a valid IPv4 subnet, or {@code false} otherwise.
     */
    public static boolean isIPv4Subnet(CharSequence s) {
        return s != null && isIPv4Subnet(s, 0, s.length());
    }

    /**
     * Tests whether or not a portion of a {@code CharSequence} is a valid IPv4 subnet.
     *
     * @param s The {@code CharSequence} to test.
     * @param start The index in the {@code CharSequence} to start checking at, inclusive.
     * @param end The index in the {@code CharSequence} to end checking at, exclusive.
     * @return {@code true} if the {@code CharSequence} is a valid IPv4 subnet, or {@code false} otherwise.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public static boolean isIPv4Subnet(CharSequence s, int start, int end) {
        if (s == null) {
            return false;
        }
        int index = indexOf(s, '/', start, end);
        if (index == -1) {
            return false;
        }
        int prefixLength = tryParseInt(s, index + 1, end).orElse(-1);
        if (0 <= prefixLength && prefixLength <= IPv4Address.BITS) {
            return IPAddressFormatter.ipv4().tryParse(s, start, index)
                    .map(ip -> ip.isValidRoutingPrefix(prefixLength))
                    .orElse(false);
        }
        return false;
    }
}
