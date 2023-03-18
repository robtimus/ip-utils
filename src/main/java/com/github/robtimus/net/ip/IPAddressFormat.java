/*
 * IPAddressFormat.java
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

import java.text.FieldPosition;
import java.text.Format;
import java.text.ParseException;
import java.text.ParsePosition;

/**
 * A class for formatting and parsing IP addresses.
 * Instances returned from the {@link IPAddressFormatter#asFormat() asFormat} method of an {@link IPAddressFormatter} are immutable.
 *
 * @author Rob Spoor
 * @param <IP> The supported type of IP address.
 * @since 1.2
 */
public abstract class IPAddressFormat<IP extends IPAddress<?>> extends Format {

    private static final long serialVersionUID = 3924951358401713342L;

    IPAddressFormat() {
        super();
    }

    /**
     * Formats an IP address and appends the resulting text to the given {@code StringBuffer}.
     * This method supports {@link IPAddress IPAddresses} of the correct type, and byte arrays of the correct size.
     * For instance, an {@code IPAddressFormat} for {@link IPv4Address} only supports {@link IPv4Address} and arrays of {@code 4} bytes,
     * and an {@code IPAddressFormat} for {@link IPv6Address} only supports {@link IPv6Address} and arrays of {@code 16} bytes,
     *
     * @param obj The object to format.
     * @param toAppendTo The {@code StringBuffer} to append to.
     * @param pos A {@code FieldPosition} identifying a field in the formatted text; ignored.
     * @return The given {@code StringBuffer}.
     * @throws NullPointerException If the given {@code StringBuffer} is {@code null}.
     * @throws IllegalArgumentException If the given object is not an {@link IPAddress} of the correct type or byte array of the correct size.
     */
    @Override
    public StringBuffer format(Object obj, StringBuffer toAppendTo, FieldPosition pos) {
        return formatter().format(obj, toAppendTo);
    }

    @Override
    public IP parseObject(String source, ParsePosition position) {
        return parse(source, position);
    }

    @Override
    @SuppressWarnings("unchecked")
    public IP parseObject(String source) throws ParseException {
        return (IP) super.parseObject(source);
    }

    /**
     * Attempts to parse a {@code CharSequence} to an IP address. Parsing starts at the current index of the given {@code ParsePosition}.
     * <p>
     * If parsing succeeds, the given {@code ParsePosition}'s index is updated to the
     * index after the last character that was used for parsing. The updated position can be used as a starting point for other parsing.
     * <p>
     * If parsing fails, the given {@code ParsePosition}'s index is not modified, but its error index is set to the index of the character that
     * caused parsing to fail.
     *
     * @param source The {@code CharSequence} to parse.
     * @param position The {@code ParsePosition} to update as described.
     * @return The parsed IP address if parsing succeeded, or {@code null} if parsing fails.
     * @throws NullPointerException If the given {@code CharSequence} or {@code ParsePosition} is {@code null}.
     */
    public IP parse(CharSequence source, ParsePosition position) {
        return formatter().parse(source, position);
    }

    /**
     * Parses a {@code CharSequence} to an IP address. This method is like {@link #parseObject(String)}, but unlike that method this method will use
     * the entire {@code CharSequence}.
     *
     * @param source The {@code CharSequence} to parse.
     * @return The parsed IP address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws ParseException If the {@code CharSequence} could not be parsed to an IP address.
     */
    public IP parse(CharSequence source) throws ParseException {
        return formatter().parse(source);
    }

    abstract IPAddressFormatter<IP> formatter();

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != getClass()) {
            return false;
        }
        IPAddressFormat<?> other = (IPAddressFormat<?>) o;
        return formatter().equals(other.formatter());
    }

    @Override
    public final int hashCode() {
        return formatter().hashCode();
    }

    /**
     * {@inheritDoc}
     *
     * @deprecated {@code IPAddressFormat} instances are immutable, and should not be cloned.
     */
    @Override
    @Deprecated
    public Object clone() {
        return super.clone();
    }
}
