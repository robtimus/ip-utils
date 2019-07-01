/*
 * IPv6Subnet.java
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
 * Represents a subnet of IPv6 addresses.
 *
 * @author Rob Spoor
 */
public final class IPv6Subnet extends Subnet<IPv6Address> implements IPv6Range {

    // Since only 2^31 - 1 is available, Integer.MAX_VALUE if (128 - routingPrefix) >= 31 or routingPrefix <= 128 - 31
    private static final int MIN_PREFIX_LENGTH_FOR_SIZE = IPv6Address.BITS - 31;

    private final int size;

    IPv6Subnet(IPv6Address from, IPv6Address to, int prefixLength) {
        super(from, to, prefixLength);
        size = prefixLength <= MIN_PREFIX_LENGTH_FOR_SIZE ? Integer.MAX_VALUE : 1 << (IPv6Address.BITS - prefixLength);
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public Spliterator<IPv6Address> spliterator() {
        return new IPv6RangeSpliterator(this);
    }

    /**
     * Returns an IPv6 subnet represented by a CIDR notation.
     *
     * @param cidrNotation The CIDR notation representing the IPv6 subnet.
     * @return An IPv6 subnet represented by the given CIDR notation.
     * @throws NullPointerException If the given CIDR notation is {@code null}.
     * @throws IllegalArgumentException If the given CIDR notation is invalid.
     */
    public static IPv6Subnet valueOf(CharSequence cidrNotation) {
        int index = indexOf(cidrNotation, '/');
        if (index == -1) {
            throw new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation));
        }
        IPv6Address routingPrefix = IPAddressFormatter.ipv6WithDefaults().tryParse(new SubSequence(cidrNotation, 0, index))
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        int prefixLength = tryParseInt(cidrNotation, index + 1, cidrNotation.length())
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        return valueOf(routingPrefix, prefixLength);
    }

    /**
     * Attempts to return an IPv6 subnet represented by a {@code CharSequence}.
     *
     * @param cidrNotation The possible CIDR notation representing the IPv6 subnet.
     * @return An {@link Optional} with the IPv6 subnet represented by the given CIDR notation,
     *         or {@link Optional#empty()} if the given CIDR notation is {@code null} or invalid.
     */
    public static Optional<IPv6Subnet> tryValueOfIPv6(CharSequence cidrNotation) {
        if (cidrNotation == null) {
            return Optional.empty();
        }
        int index = indexOf(cidrNotation, '/');
        if (index == -1) {
            return Optional.empty();
        }
        int prefixLength = tryParseInt(cidrNotation, index + 1, cidrNotation.length()).orElse(-1);
        if (0 <= prefixLength && prefixLength <= IPv6Address.BITS) {
            return IPAddressFormatter.ipv6WithDefaults().tryParse(new SubSequence(cidrNotation, 0, index))
                    .filter(ip -> ip.isValidRoutingPrefix(prefixLength))
                    .map(ip -> valueOf(ip, prefixLength));
        }
        return Optional.empty();
    }

    /**
     * Returns an IPv6 subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the IPv6 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code ffff:ffff::} is valid for prefix length {@code 32}, but {@code ffff:ffff::1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv6 subnet.
     * @param prefixLength The length of the prefix of the IPv6 subnet.
     * @return An IPv6 subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the IPv6 subnet of the given prefix length that
     *                                      contains the routing prefix.
     */
    public static IPv6Subnet valueOf(IPv6Address routingPrefix, int prefixLength) {
        return routingPrefix.startingSubnet(prefixLength);
    }

    /**
     * Returns an IPv6 subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the IPv6 subnet of the given prefix length that contains the routing prefix.
     * For example, {@code ffff:ffff::} is valid for prefix length {@code 32}, but {@code ffff:ffff::1} is not.
     *
     * @param routingPrefix The routing prefix of the IPv6 subnet.
     * @param prefixLength The length of the prefix of the IPv6 subnet.
     * @return An IPv6 subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given routing prefix does not represent a valid IP address,
     *                                      or if the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the IPv6 subnet of the given prefix length that
     *                                      contains the routing prefix.
     * @see #valueOf(IPv6Address, int)
     */
    public static IPv6Subnet valueOf(CharSequence routingPrefix, int prefixLength) {
        return valueOf(IPv6Address.valueOf(routingPrefix), prefixLength);
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid IPv6 subnet.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the {@code CharSequence} is a valid IPv6 subnet, or {@code false} otherwise.
     */
    public static boolean isIPv6Subnet(CharSequence s) {
        if (s == null) {
            return false;
        }
        int index = indexOf(s, '/');
        if (index == -1) {
            return false;
        }
        int prefixLength = tryParseInt(s, index + 1, s.length()).orElse(-1);
        if (0 <= prefixLength && prefixLength <= IPv6Address.BITS) {
            return IPAddressFormatter.ipv6WithDefaults().tryParse(new SubSequence(s, 0, index))
                    .map(ip -> ip.isValidRoutingPrefix(prefixLength))
                    .orElse(false);
        }
        return false;
    }
}
