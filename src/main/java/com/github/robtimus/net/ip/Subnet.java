/*
 * Subnet.java
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

/**
 * Represents a subnet of IP addresses.
 *
 * @author Rob Spoor
 * @param <IP> The type of IP address in the subnet.
 */
public abstract class Subnet<IP extends IPAddress<IP>> extends AbstractIPRange<IP> {

    private final IP from;
    private final IP to;
    private final int prefixLength;

    private String stringValue;

    Subnet(IP from, IP to, int prefixLength) {
        this.from = from;
        this.to = to;
        this.prefixLength = prefixLength;
    }

    @Override
    public final IP from() {
        return from;
    }

    @Override
    public final IP to() {
        return to;
    }

    /**
     * Returns the routing prefix of this subnet.
     *
     * @return The routing prefix of this subnet.
     */
    public final IP routingPrefix() {
        return from();
    }

    /**
     * Returns the length of the prefix of this subnet.
     *
     * @return The length of the prefix of this subnet.
     */
    public final int prefixLength() {
        return prefixLength;
    }

    @Override
    @SuppressWarnings("nls")
    public String toString() {
        if (stringValue == null) {
            stringValue = from + "/" + prefixLength;
        }
        return stringValue;
    }

    /**
     * Returns a subnet represented by a CIDR notation.
     *
     * @param cidrNotation The CIDR notation representing the subnet.
     * @return A subnet represented by the given CIDR notation.
     * @throws NullPointerException If the given CIDR notation is {@code null}.
     * @throws IllegalArgumentException If the given CIDR notation is invalid.
     */
    public static Subnet<?> valueOf(CharSequence cidrNotation) {
        int index = indexOf(cidrNotation, '/');
        if (index == -1) {
            throw new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation));
        }
        IPAddress<?> routingPrefix = IPAddressFormatter.anyVersionWithDefaults().tryParse(new SubSequence(cidrNotation, 0, index))
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        int prefixLength = tryParseInt(cidrNotation, index + 1, cidrNotation.length())
                .orElseThrow(() -> new IllegalArgumentException(Messages.Subnet.invalidCIDRNotation.get(cidrNotation)));
        return valueOf(routingPrefix, prefixLength);
    }

    /**
     * Attempts to return a subnet represented by a {@code CharSequence}.
     *
     * @param cidrNotation The possible CIDR notation representing the subnet.
     * @return An {@link Optional} with the subnet represented by the given CIDR notation, or {@link Optional#empty()} if the given CIDR notation is
     *         {@code null} or invalid.
     */
    public static Optional<Subnet<?>> tryValueOf(CharSequence cidrNotation) {
        if (cidrNotation == null) {
            return Optional.empty();
        }
        int index = indexOf(cidrNotation, '/');
        if (index == -1) {
            return Optional.empty();
        }
        int prefixLength = tryParseInt(cidrNotation, index + 1, cidrNotation.length()).orElse(-1);
        if (0 <= prefixLength) {
            return IPAddressFormatter.anyVersionWithDefaults().tryParse(new SubSequence(cidrNotation, 0, index))
                    .filter(ip -> prefixLength <= ip.bits() && ip.isValidRoutingPrefix(prefixLength))
                    .map(ip -> valueOf(ip, prefixLength));
        }
        return Optional.empty();
    }

    static int indexOf(CharSequence s, char c) {
        for (int i = 0; i < s.length(); i++) {
            if (c == s.charAt(i)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Returns a subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the subnet.
     * @param prefixLength The length of the prefix of the subnet.
     * @return A subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the subnet of the given prefix length that contains
     *                                      the routing prefix.
     */
    public static Subnet<?> valueOf(IPAddress<?> routingPrefix, int prefixLength) {
        return routingPrefix.startingSubnet(prefixLength);
    }

    /**
     * Returns a subnet represented by a routing prefix and a prefix length.
     * The given routing prefix must be the start of the subnet of the given prefix length that contains the routing prefix.
     * For example, {@code 192.168.0.0} is valid for prefix length {@code 16}, but {@code 192.168.0.1} is not.
     *
     * @param routingPrefix The routing prefix of the subnet.
     * @param prefixLength The length of the prefix of the subnet.
     * @return A subnet represented by the given routing prefix and prefix length.
     * @throws NullPointerException If the given routing prefix is {@code null}.
     * @throws IllegalArgumentException If the given routing prefix does not represent a valid IP address,
     *                                      or if the given prefix length is not valid for the IP address,
     *                                      or if the given routing prefix is not the start of the subnet of the given prefix length that contains
     *                                      the routing prefix.
     * @see #valueOf(IPAddress, int)
     */
    public static Subnet<?> valueOf(CharSequence routingPrefix, int prefixLength) {
        return valueOf(IPAddress.valueOf(routingPrefix), prefixLength);
    }

    /**
     * Tests whether or not a {@code CharSequence} is a valid subnet.
     *
     * @param s The {@code CharSequence} to test.
     * @return {@code true} if the {@code CharSequence} is a valid subnet, or {@code false} otherwise.
     */
    public static boolean isSubnet(CharSequence s) {
        return IPv4Subnet.isIPv4Subnet(s) || IPv6Subnet.isIPv6Subnet(s);
    }
}
