/*
 * IPAddressFormatter.java
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

import static com.github.robtimus.net.ip.Bytes.HMASK;
import static com.github.robtimus.net.ip.Bytes.HSHIFT;
import static com.github.robtimus.net.ip.Bytes.HSHIFT3;
import static com.github.robtimus.net.ip.Bytes.OMASK;
import static com.github.robtimus.net.ip.Bytes.OSHIFT0;
import static com.github.robtimus.net.ip.Bytes.OSHIFT1;
import static com.github.robtimus.net.ip.Bytes.OSHIFT2;
import static com.github.robtimus.net.ip.Bytes.OSHIFT3;
import static com.github.robtimus.net.ip.Bytes.addressToHighAddress;
import static com.github.robtimus.net.ip.Bytes.addressToLowAddress;
import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.text.Format;
import java.text.ParseException;
import java.text.ParsePosition;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Formatter for printing and parsing IP addresses. Instances returned from one of the factory methods or a {@link Builder} are immutable.
 *
 * @author Rob Spoor
 * @param <IP> The supported type of IP address.
 */
public abstract class IPAddressFormatter<IP extends IPAddress<?>> {

    private IPAddressFormatter() {
        super();
    }

    /**
     * Formats an IP address, appending it to a {@code StringBuilder}.
     *
     * @param address The IP address to format.
     * @param sb The {@code StringBuilder} to append to.
     * @return The given {@code StringBuilder}.
     * @throws NullPointerException If the given IP address or {@code StringBuilder} is {@code null}.
     */
    public StringBuilder format(IP address, StringBuilder sb) {
        return appendNoThrows(address, sb);
    }

    /**
     * Formats an IP address, appending it to a {@code StringBuffer}.
     *
     * @param address The IP address to format.
     * @param sb The {@code StringBuffer} to append to.
     * @return The given {@code StringBuffer}.
     * @throws NullPointerException If the given IP address or {@code StringBuffer} is {@code null}.
     * @since 1.2
     */
    public StringBuffer format(IP address, StringBuffer sb) {
        return appendNoThrows(address, sb);
    }

    /**
     * Formats an IP address.
     *
     * @param address The IP address to format.
     * @return The formatted IP address.
     * @throws NullPointerException If the given IP address is {@code null}.
     */
    public abstract String format(IP address);

    /**
     * Appends an IP address to an {@code Appendable}.
     *
     * @param <A> The type of {@code Appendable}.
     * @param address The IP address to append.
     * @param dest The {@code Appendable} to append to.
     * @return The given {@code Appendable}.
     * @throws NullPointerException If the given IP address or {@code Appendable} is {@code null}.
     * @throws IOException If an I/O error occurs while appending to the {@code Appendable}.
     * @since 1.1
     */
    public abstract <A extends Appendable> A append(IP address, A dest) throws IOException;

    private <A extends Appendable> A appendNoThrows(IP address, A dest) {
        try {
            return append(address, dest);
        } catch (IOException e) {
            // will not occur because the Appendable will not throw any IOExceptions
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Formats an IP address, appending it to a {@code StringBuilder}.
     *
     * @param address A byte array representing the IP address to format.
     * @param sb The {@code StringBuilder} to append to.
     * @return The given {@code StringBuilder}.
     * @throws NullPointerException If the given array or {@code StringBuilder} is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is invalid.
     */
    public StringBuilder format(byte[] address, StringBuilder sb) {
        return appendNoThrows(address, sb);
    }

    /**
     * Formats an IP address, appending it to a {@code StringBuffer}.
     *
     * @param address A byte array representing the IP address to format.
     * @param sb The {@code StringBuffer} to append to.
     * @return The given {@code StringBuffer}.
     * @throws NullPointerException If the given array or {@code StringBuffer} is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is invalid.
     * @since 1.2
     */
    public StringBuffer format(byte[] address, StringBuffer sb) {
        return appendNoThrows(address, sb);
    }

    /**
     * Formats an IP address.
     *
     * @param address A byte array representing the IP address to format.
     * @return The formatted IP address.
     * @throws NullPointerException If the given array is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is invalid.
     */
    public abstract String format(byte[] address);

    /**
     * Appends an IP address to an {@code Appendable}.
     *
     * @param <A> The type of {@code Appendable}.
     * @param address A byte array representing the IP address to format.
     * @param dest The {@code Appendable} to append to.
     * @return The given {@code Appendable}.
     * @throws NullPointerException If the given array or {@code Appendable} is {@code null}.
     * @throws IllegalArgumentException If the length of the given array is invalid.
     * @throws IOException If an I/O error occurs while appending to the {@code Appendable}.
     * @since 1.1
     */
    public abstract <A extends Appendable> A append(byte[] address, A dest) throws IOException;

    private <A extends Appendable> A appendNoThrows(byte[] address, A dest) {
        try {
            return append(address, dest);
        } catch (IOException e) {
            // will not occur because the Appendable will not throw any IOExceptions
            throw new UncheckedIOException(e);
        }
    }

    abstract StringBuffer format(Object object, StringBuffer dest);

    abstract IP valueOf(CharSequence address, int start, int end);

    abstract IP valueOf(CharSequence address, int start, int end, Function<CharSequence, String> errorMessage);

    /**
     * Parses a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @return The parsed IP address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws ParseException If the {@code CharSequence} could not be parsed to an IP address.
     */
    public IP parse(CharSequence source) throws ParseException {
        return parse(source, 0, source.length());
    }

    /**
     * Parses a portion of a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @param start The start index in the {@code CharSequence} to start parsing, inclusive.
     * @param end The end index in the {@code CharSequence} to end parsing, exclusive.
     * @return The parsed IP address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws ParseException If the {@code CharSequence} could not be parsed to an IP address.
     * @since 1.1
     */
    public abstract IP parse(CharSequence source, int start, int end) throws ParseException;

    abstract IP parse(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException;

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
    public abstract IP parse(CharSequence source, ParsePosition position);

    /**
     * Attempts to parse a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @return An {@code Optional} with the parsed IP address if parsing succeeded, or {@code Optional#empty()} if parsing fails.
     */
    public Optional<IP> tryParse(CharSequence source) {
        return source == null ? Optional.empty() : tryParse(source, 0, source.length());
    }

    /**
     * Attempts to parse a portion of a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @param start The start index in the {@code CharSequence} to start parsing, inclusive.
     * @param end The end index in the {@code CharSequence} to end parsing, exclusive.
     * @return An {@code Optional} with the parsed IP address if parsing succeeded, or {@code Optional#empty()} if parsing fails.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public abstract Optional<IP> tryParse(CharSequence source, int start, int end);

    /**
     * Parses a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @return A byte array representing the parsed IP address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws ParseException If the {@code CharSequence} could not be parsed to an IP address.
     */
    public byte[] parseToBytes(CharSequence source) throws ParseException {
        return parseToBytes(source, 0, source.length());
    }

    /**
     * Parses a portion of a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @param start The start index in the {@code CharSequence} to start parsing, inclusive.
     * @param end The end index in the {@code CharSequence} to end parsing, exclusive.
     * @return A byte array representing the parsed IP address.
     * @throws NullPointerException If the given {@code CharSequence} is {@code null}.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index.
     * @throws ParseException If the {@code CharSequence} could not be parsed to an IP address.
     * @since 1.1
     */
    public abstract byte[] parseToBytes(CharSequence source, int start, int end) throws ParseException;

    abstract byte[] parseToBytes(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException;

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
     * @return A byte array representing the parsed IP address if parsing succeeded, or {@code null} if parsing fails.
     * @throws NullPointerException If the given {@code CharSequence} or {@code ParsePosition} is {@code null}.
     */
    public abstract byte[] parseToBytes(CharSequence source, ParsePosition position);

    /**
     * Attempts to parse a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @return An {@code Optional} with a byte array representing the parsed IP address if parsing succeeded,
     *         or {@code Optional#empty()} if parsing fails.
     */
    public Optional<byte[]> tryParseToBytes(CharSequence source) {
        return source == null ? Optional.empty() : tryParseToBytes(source, 0, source.length());
    }

    /**
     * Attempts to parse a portion of a {@code CharSequence} to an IP address.
     *
     * @param source The {@code CharSequence} to parse.
     * @param start The start index in the {@code CharSequence} to start parsing, inclusive.
     * @param end The end index in the {@code CharSequence} to end parsing, exclusive.
     * @return An {@code Optional} with a byte array representing the parsed IP address if parsing succeeded,
     *         or {@code Optional#empty()} if parsing fails.
     * @throws IndexOutOfBoundsException If the start index is negative, or if the end index is larger than the length of the {@code CharSequence},
     *                                       or if the start index is larger than the end index (unless if the {@code CharSequence} is {@code null}).
     * @since 1.1
     */
    public abstract Optional<byte[]> tryParseToBytes(CharSequence source, int start, int end);

    /**
     * Returns an {@link IPAddressFormat} that delegates to this object.
     * As a result, its formatting and parsing with a {@link ParsePosition} will be identical to the printing and parsing of this object.
     * However, its {@link IPAddressFormat#parseObject(String) parseObject(String)} method behaves slightly differently - as per the contract of
     * {@link Format#parseObject(String)}, it may not use the entire input for its parsing.
     * Its {@link IPAddressFormat#parse(CharSequence) parse(CharSequence)} method on the other hand will use the entire input.
     *
     * @return An {@link IPAddressFormat} that delegates to this object.
     * @see #parse(CharSequence, ParsePosition)
     * @see #format(IPAddress, StringBuffer)
     * @see #format(byte[], StringBuffer)
     * @since 1.2
     */
    public abstract IPAddressFormat<IP> asFormat();

    abstract boolean isValid(CharSequence source, int start, int end);

    abstract boolean testIfValid(CharSequence source, Predicate<? super IP> predicate);

    static void checkBounds(CharSequence s, int start, int end) {
        if (start < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (end > s.length()) {
            throw new IndexOutOfBoundsException();
        }
        if (start > end) {
            throw new IndexOutOfBoundsException();
        }
    }

    /**
     * Returns a formatter for printing and parsing IPv4 addresses.
     *
     * @return A formatter for printing and parsing IPv4 addresses.
     */
    public static IPAddressFormatter<IPv4Address> ipv4() {
        return IPv4.INSTANCE;
    }

    /**
     * Returns a formatter for printing and parsing IPv6 addresses.
     * When printing IPv6 addresses, it will use a short format that will omit the longest consecutive section of zeroes.
     * For example, it will print {@code ::1} or {@code ::} and not {@code 0:0:0:0:0:0:0:1} or {@code 0:0:0:0:0:0:0:0}.
     *
     * @return A formatter for printing and parsing IPv6 addresses.
     */
    public static IPAddressFormatter<IPv6Address> ipv6WithDefaults() {
        return IPv6.DEFAULT_INSTANCE;
    }

    /**
     * Returns a formatter for printing and parsing IP addresses of any version.
     * When printing IPv6 addresses, it will use a short format that will omit the longest consecutive section of zeroes.
     * For example, it will print {@code ::1} or {@code ::} and not {@code 0:0:0:0:0:0:0:1} or {@code 0:0:0:0:0:0:0:0}.
     *
     * @return A formatter for printing and parsing IP addresses of any version.
     */
    public static IPAddressFormatter<IPAddress<?>> anyVersionWithDefaults() {
        return AnyVersion.DEFAULT_INSTANCE;
    }

    /**
     * Returns a new builder for formatters for printing and parsing IPv6 addresses.
     * <p>
     * Note: the builder specific settings are only relevant for printing. If only parsing is required, use {@link #ipv6WithDefaults()} instead.
     *
     * @return A new builder for formatters for printing and parsing IPv6 addresses.
     */
    public static Builder<IPv6Address> ipv6() {
        return new Builder<>(IPv6::valueOf);
    }

    /**
     * Returns a new builder for formatters for printing and parsing IP addresses of any version.
     * <p>
     * Note: the builder specific settings are only relevant for printing. If only parsing is required, use {@link #ipv6WithDefaults()} instead.
     *
     * @return A new builder for formatters for printing and parsing IP addresses of any version.
     */
    public static Builder<IPAddress<?>> anyVersion() {
        return new Builder<>(AnyVersion::valueOf);
    }

    /**
     * A builder for formatters for printing and parsing IP addresses.
     *
     * @author Rob Spoor
     * @param <IP> The supported type of IP address for built formatters.
     */
    public static final class Builder<IP extends IPAddress<?>> {

        private final Constructor<IP> constructor;

        private FormatStyle style = FormatStyle.SHORT;
        private boolean upperCase = false;
        private boolean withIPv4End = false;
        private boolean encloseInBrackets = false;

        private Builder(Constructor<IP> constructor) {
            this.constructor = constructor;
        }

        /**
         * Specifies that created formatters will format IPv6 addresses in short style.
         * This short form will omit consecutive sections of zeroes if possible, and hextets will not contain any leading zeroes.
         * If there are two or more consecutive sections of zeroes, the longest section will be selected.
         * For example, {@code ::1} will be formatted as {@code ::1}, and {@code 0:0:1:0:0:0:0:1} will be formatted as {@code 0:0:1::1}.
         * This setting is ignored when formatting IPv4 addresses.
         * <p>
         * This is the default setting.
         *
         * @return This builder object.
         */
        public Builder<IP> withShortStyle() {
            style = FormatStyle.SHORT;
            return this;
        }

        /**
         * Specifies that created formatters will format IPv6 addresses in medium style.
         * This medium form will not omit consecutive sections of zeroes, but hextets will not contain any leading zeroes.
         * For example, {@code ::1} will be formatted as {@code 0:0:0:0:0:0:0:1}.
         * This setting is ignored when formatting IPv4 addresses.
         *
         * @return This builder object.
         */
        public Builder<IP> withMediumStyle() {
            style = FormatStyle.MEDIUM;
            return this;
        }

        /**
         * Specifies that created formatters will format IPv6 addresses in long style.
         * This long form will not omit consecutive sections of zeroes, and each hextet will be four characters long.
         * For example, {@code ::1} will be formatted as {@code 0000:0000:0000:0000:0000:0000:0000:0001}.
         * This setting is ignored when formatting IPv4 addresses.
         *
         * @return This builder object.
         */
        public Builder<IP> withLongStyle() {
            style = FormatStyle.LONG;
            return this;
        }

        /**
         * Specifies that created formatters will format IPv6 addresses in upper case.
         * This setting is ignored when formatting IPv4 addresses.
         *
         * @return This builder object.
         */
        public Builder<IP> toUpperCase() {
            upperCase = true;
            return this;
        }

        /**
         * Specifies that created formatters will format IPv6 addresses in lower case.
         * This setting is ignored when formatting IPv4 addresses.
         * <p>
         * This is the default setting.
         *
         * @return This builder object.
         */
        public Builder<IP> toLowerCase() {
            upperCase = false;
            return this;
        }

        /**
         * Specifies that created formatters will format the last {@code 4} bytes of IPv6 addresses as an IPv4 address.
         * For example, {@code ::1} will be formatted as {@code ::0.0.0.1}, {@code 0:0:0:0:0:0:0.0.0.1} or
         * {@code 0000:0000:0000:0000:0000:0000:0.0.0.1}, depending on the style.
         * This setting is ignored when formatting IPv4 addresses.
         *
         * @return This builder object.
         */
        public Builder<IP> withIPv4End() {
            withIPv4End = true;
            return this;
        }

        /**
         * Specifies that created formatters will format the last {@code 4} bytes of IPv6 addresses as two hextets, not as an IPv4 address.
         * This setting is ignored when formatting IPv4 addresses.
         * <p>
         * This is the default setting.
         *
         * @return This builder object.
         */
        public Builder<IP> withoutIPv4End() {
            withIPv4End = false;
            return this;
        }

        /**
         * Specifies that created formatters will enclose formatted IPv6 addresses in brackets.
         * For example, {@code ::1} will be formatted as {@code [::1]}, {@code [0:0:0:0:0:0:0:1]} or
         * {@code [0000:0000:0000:0000:0000:0000:0000:0001]}, depending on the style.
         * This setting is ignored when formatting IPv4 addresses.
         *
         * @return This builder object.
         */
        public Builder<IP> enclosingInBrackets() {
            encloseInBrackets = true;
            return this;
        }

        /**
         * Specifies that created formatters will not enclose formatted IPv6 addresses in brackets.
         * This setting is ignored when formatting IPv4 addresses.
         * <p>
         * This is the default setting.
         *
         * @return This builder object.
         */
        public Builder<IP> notEnclosingInBrackets() {
            encloseInBrackets = false;
            return this;
        }

        /**
         * Specifies that the default settings should be restored. Calling this method is similar to calling {@link #withShortStyle()},
         * {@link #toLowerCase()}, {@link #withoutIPv4End()} and {@link #notEnclosingInBrackets()}.
         *
         * @return This builder object.
         */
        public Builder<IP> withDefaults() {
            withShortStyle();
            toLowerCase();
            withoutIPv4End();
            notEnclosingInBrackets();
            return this;
        }

        /**
         * This method allows the application of a function to this builder object.
         * <p>
         * Any exception thrown by the function will be propagated to the caller.
         *
         * @param <R> The type of the result of the function.
         * @param f The function to apply.
         * @return The result of applying the function to this builder object.
         * @since 1.3
         */
        public <R> R transform(Function<? super Builder<?>, ? extends R> f) {
            return f.apply(this);
        }

        /**
         * Returns a formatter for printing and parsing IP addresses with the current settings of this builder object.
         *
         * @return A formatter for printing and parsing IP addresses with the current settings of this builder object.
         */
        public IPAddressFormatter<IP> build() {
            return constructor.create(style, upperCase, withIPv4End, encloseInBrackets);
        }

        private interface Constructor<IP extends IPAddress<?>> {

            IPAddressFormatter<IP> create(FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets);
        }
    }

    private static final class IPv4 extends IPAddressFormatter<IPv4Address> {

        private static final IPv4 INSTANCE = new IPv4();

        // max length is 3 * octets plus a dot between each
        private static final int MAX_LENGTH = IPv4Address.OCTETS * 3 + (IPv4Address.OCTETS - 1);

        @Override
        public String format(IPv4Address address) {
            return format(address, new StringBuilder(MAX_LENGTH)).toString();
        }

        @Override
        public <A extends Appendable> A append(IPv4Address address, A appendable) throws IOException {
            append(address.address, appendable);
            return appendable;
        }

        void append(int address, Appendable appendable) throws IOException {
            appendOctet((address >> OSHIFT3) & OMASK, appendable);
            appendable.append('.');
            appendOctet((address >> OSHIFT2) & OMASK, appendable);
            appendable.append('.');
            appendOctet((address >> OSHIFT1) & OMASK, appendable);
            appendable.append('.');
            appendOctet((address >> OSHIFT0) & OMASK, appendable);
        }

        @Override
        public String format(byte[] address) {
            return format(address, new StringBuilder(MAX_LENGTH)).toString();
        }

        @Override
        public <A extends Appendable> A append(byte[] address, A appendable) throws IOException {
            if (address.length != IPv4Address.BYTES) {
                throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
            }
            appendOctet(address[0] & OMASK, appendable);
            appendable.append('.');
            appendOctet(address[1] & OMASK, appendable);
            appendable.append('.');
            appendOctet(address[2] & OMASK, appendable);
            appendable.append('.');
            appendOctet(address[3] & OMASK, appendable);
            return appendable;
        }

        void appendOctet(int octet, Appendable dest) throws IOException {
            boolean added = false;

            added = appendChar(octet / 100, dest, added);
            appendChar((octet % 100) / 10, dest, added);
            appendChar(octet % 10, dest, true);
        }

        private boolean appendChar(int i, Appendable dest, boolean addIfZero) throws IOException {
            if (i != 0 || addIfZero) {
                char c = Character.forDigit(i, 16);
                dest.append(c);
                return true;
            }
            return false;
        }

        @Override
        StringBuffer format(Object object, StringBuffer dest) {
            if (object instanceof IPv4Address) {
                return format((IPv4Address) object, dest);
            }
            if (object instanceof byte[]) {
                return format((byte[]) object, dest);
            }
            throw new IllegalArgumentException(Messages.IPAddressFormat.unformattableObject.get(object));
        }

        @Override
        IPv4Address valueOf(CharSequence address, int start, int end) {
            return valueOf(address, start, end, Messages.IPv4Address.invalidIPv4Address::get);
        }

        @Override
        IPv4Address valueOf(CharSequence address, int start, int end, Function<CharSequence, String> errorMessage) {
            Objects.requireNonNull(address);
            checkBounds(address, start, end);
            Parser parser = new Parser(address, start, end, true);
            if (parser.parse()) {
                return IPv4Address.valueOf(parser.address);
            }
            throw new IllegalArgumentException(errorMessage.apply(address));
        }

        @Override
        public IPv4Address parse(CharSequence source, int start, int end) throws ParseException {
            return parse(source, start, end, Messages.IPv4Address.parseError::get);
        }

        @Override
        IPv4Address parse(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            Objects.requireNonNull(source);
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            if (parser.parse()) {
                return IPv4Address.valueOf(parser.address);
            }
            throw new ParseException(errorMessage.apply(source), parser.errorIndex);
        }

        @Override
        public IPv4Address parse(CharSequence source, ParsePosition position) {
            Objects.requireNonNull(source);
            Parser parser = new Parser(source, position.getIndex(), source.length(), false);
            if (parser.parse()) {
                position.setIndex(parser.index);
                return IPv4Address.valueOf(parser.address);
            }
            position.setErrorIndex(parser.errorIndex);
            return null;
        }

        @Override
        public Optional<IPv4Address> tryParse(CharSequence source, int start, int end) {
            if (source == null) {
                return Optional.empty();
            }
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            return parser.parse() ? Optional.of(IPv4Address.valueOf(parser.address)) : Optional.empty();
        }

        @Override
        public byte[] parseToBytes(CharSequence source, int start, int end) throws ParseException {
            return parseToBytes(source, start, end, Messages.IPv4Address.parseError::get);
        }

        @Override
        byte[] parseToBytes(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            Objects.requireNonNull(source);
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            if (parser.parse()) {
                return Bytes.intToAddress(parser.address);
            }
            throw new ParseException(errorMessage.apply(source), parser.errorIndex);
        }

        @Override
        public byte[] parseToBytes(CharSequence source, ParsePosition position) {
            Objects.requireNonNull(source);
            Parser parser = new Parser(source, position.getIndex(), source.length(), false);
            if (parser.parse()) {
                position.setIndex(parser.index);
                return Bytes.intToAddress(parser.address);
            }
            position.setErrorIndex(parser.errorIndex);
            return null;
        }

        @Override
        public Optional<byte[]> tryParseToBytes(CharSequence source, int start, int end) {
            if (source == null) {
                return Optional.empty();
            }
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            return parser.parse() ? Optional.of(Bytes.intToAddress(parser.address)) : Optional.empty();
        }

        @Override
        public IPAddressFormat<IPv4Address> asFormat() {
            return IPv4Format.INSTANCE;
        }

        @Override
        boolean isValid(CharSequence source, int start, int end) {
            if (source == null) {
                return false;
            }
            checkBounds(source, start, end);
            return new Parser(source, start, end, true).parse();
        }

        @Override
        boolean testIfValid(CharSequence source, Predicate<? super IPv4Address> predicate) {
            if (source == null) {
                return false;
            }
            Parser parser = new Parser(source, 0, source.length(), true);
            return parser.parse() && predicate.test(IPv4Address.valueOf(parser.address));
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormatter.class.getName() + "#IPv4";
        }

        private static final class Parser {

            private final CharSequence source;
            private final int end;
            private final boolean parseAll;

            private int index;
            private int errorIndex;

            private int address = 0;

            private Parser(CharSequence source, int start, int end, boolean parseAll) {
                this.source = source;
                this.end = end;
                this.parseAll = parseAll;

                index = start;
                errorIndex = -1;
            }

            private boolean parse() {
                return parseOctet()
                        && parseDot() && parseOctet()
                        && parseDot() && parseOctet()
                        && parseDot() && parseOctet()
                        && parseEnd();
            }

            private boolean parseOctet() {
                int octet = 0;
                int digits;
                // octets are in decimal, so maximum 3 digits long
                for (digits = 0; digits < 3 && index < end; digits++, index++) {
                    char c = source.charAt(index);
                    int d = Character.digit(c, 10);
                    if (d == -1) {
                        // not part of an octet
                        break;
                    }
                    int newValue = 10 * octet + d;
                    if (newValue > 255) {
                        // newValue is no longer an octet
                        break;
                    }
                    octet = newValue;
                }
                if (digits == 0) {
                    errorIndex = index;
                    return false;
                }
                address = (address << OSHIFT1) | octet;
                return true;
            }

            private boolean parseDot() {
                if (index >= end || source.charAt(index) != '.') {
                    errorIndex = index;
                    return false;
                }
                index++;
                return true;
            }

            private boolean parseEnd() {
                if (parseAll && index != end) {
                    errorIndex = index;
                    return false;
                }
                return true;
            }
        }
    }

    private static final class IPv6 extends IPAddressFormatter<IPv6Address> {

        // max length is MAX(4 * hextets plus a colon between each, 4 * (hextets - 2) plus a colon between each plus a colon + IPv4 max length)
        private static final int MAX_LENGTH_NO_IPV4 = IPv6Address.HEXTETS * 4 + (IPv6Address.HEXTETS - 1);
        private static final int MAX_LENGTH_IPV4 = (IPv6Address.HEXTETS - 2) * 4 + IPv6Address.HEXTETS + IPv4.MAX_LENGTH;

        private static final IPv6[] INSTANCES = createInstances();
        private static final IPv6 DEFAULT_INSTANCE = valueOf(FormatStyle.SHORT, false, false, false);

        private final FormatStyle style;
        private final boolean upperCase;
        private final boolean withIPv4End;
        private final boolean encloseInBrackets;
        private int maxLength;

        private IPv6(FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets) {
            this.style = style;
            this.upperCase = upperCase;
            this.withIPv4End = withIPv4End;
            this.encloseInBrackets = encloseInBrackets;
            this.maxLength = (withIPv4End ? MAX_LENGTH_IPV4 : MAX_LENGTH_NO_IPV4) + (encloseInBrackets ? 2 : 0);
        }

        @Override
        public String format(IPv6Address address) {
            return format(address, new StringBuilder(maxLength)).toString();
        }

        @Override
        public <A extends Appendable> A append(IPv6Address address, A appendable) throws IOException {
            style.append(address, upperCase, withIPv4End, encloseInBrackets, appendable);
            return appendable;
        }

        @Override
        public String format(byte[] address) {
            return format(address, new StringBuilder(maxLength)).toString();
        }

        @Override
        public <A extends Appendable> A append(byte[] address, A appendable) throws IOException {
            if (address.length != IPv6Address.BYTES) {
                throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
            }
            style.append(address, upperCase, withIPv4End, encloseInBrackets, appendable);
            return appendable;
        }

        @Override
        StringBuffer format(Object object, StringBuffer dest) {
            if (object instanceof IPv6Address) {
                return format((IPv6Address) object, dest);
            }
            if (object instanceof byte[]) {
                return format((byte[]) object, dest);
            }
            throw new IllegalArgumentException(Messages.IPAddressFormat.unformattableObject.get(object));
        }

        @Override
        IPv6Address valueOf(CharSequence address, int start, int end) {
            return valueOf(address, start, end, Messages.IPv6Address.invalidIPv6Address::get);
        }

        @Override
        IPv6Address valueOf(CharSequence address, int start, int end, Function<CharSequence, String> errorMessage) {
            Objects.requireNonNull(address);
            checkBounds(address, start, end);
            Parser parser = new Parser(address, start, end, true);
            if (parser.parse()) {
                return IPv6Address.valueOf(parser.highAddress, parser.lowAddress);
            }
            throw new IllegalArgumentException(errorMessage.apply(address));
        }

        @Override
        public IPv6Address parse(CharSequence source, int start, int end) throws ParseException {
            return parse(source, start, end, Messages.IPv6Address.parseError::get);
        }

        @Override
        IPv6Address parse(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            Objects.requireNonNull(source);
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            if (parser.parse()) {
                return IPv6Address.valueOf(parser.highAddress, parser.lowAddress);
            }
            throw new ParseException(errorMessage.apply(source), parser.errorIndex);
        }

        @Override
        public IPv6Address parse(CharSequence source, ParsePosition position) {
            Objects.requireNonNull(source);
            Parser parser = new Parser(source, position.getIndex(), source.length(), false);
            if (parser.parse()) {
                position.setIndex(parser.index);
                return IPv6Address.valueOf(parser.highAddress, parser.lowAddress);
            }
            position.setErrorIndex(parser.errorIndex);
            return null;
        }

        @Override
        public Optional<IPv6Address> tryParse(CharSequence source, int start, int end) {
            if (source == null) {
                return Optional.empty();
            }
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            return parser.parse() ? Optional.of(IPv6Address.valueOf(parser.highAddress, parser.lowAddress)) : Optional.empty();
        }

        @Override
        public byte[] parseToBytes(CharSequence source, int start, int end) throws ParseException {
            return parseToBytes(source, start, end, Messages.IPv6Address.parseError::get);
        }

        @Override
        byte[] parseToBytes(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            Objects.requireNonNull(source);
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            if (parser.parse()) {
                return Bytes.longsToAddress(parser.highAddress, parser.lowAddress);
            }
            throw new ParseException(errorMessage.apply(source), parser.errorIndex);
        }

        @Override
        public byte[] parseToBytes(CharSequence source, ParsePosition position) {
            Objects.requireNonNull(source);
            Parser parser = new Parser(source, position.getIndex(), source.length(), false);
            if (parser.parse()) {
                position.setIndex(parser.index);
                return Bytes.longsToAddress(parser.highAddress, parser.lowAddress);
            }
            position.setErrorIndex(parser.errorIndex);
            return null;
        }

        @Override
        public Optional<byte[]> tryParseToBytes(CharSequence source, int start, int end) {
            if (source == null) {
                return Optional.empty();
            }
            checkBounds(source, start, end);
            Parser parser = new Parser(source, start, end, true);
            return parser.parse() ? Optional.of(Bytes.longsToAddress(parser.highAddress, parser.lowAddress)) : Optional.empty();
        }

        @Override
        public IPAddressFormat<IPv6Address> asFormat() {
            int index = indexOfInstance(style, upperCase, withIPv4End, encloseInBrackets);
            return IPv6Format.INSTANCES[index];
        }

        @Override
        boolean isValid(CharSequence source, int start, int end) {
            if (source == null) {
                return false;
            }
            checkBounds(source, start, end);
            return new Parser(source, start, end, true).parse();
        }

        @Override
        boolean testIfValid(CharSequence source, Predicate<? super IPv6Address> predicate) {
            if (source == null) {
                return false;
            }
            Parser parser = new Parser(source, 0, source.length(), true);
            return parser.parse() && predicate.test(IPv6Address.valueOf(parser.highAddress, parser.lowAddress));
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormatter.class.getName() + "#IPv6"
                    + "[style=" + style
                    + ",upperCase=" + upperCase
                    + ",withIPv4End=" + withIPv4End
                    + ",encloseInBrackets=" + encloseInBrackets
                    + "]";
        }

        private static IPv6[] createInstances() {
            int size = indexOfInstance(FormatStyle.LONG, true, true, true) + 1;
            IPv6[] instances = new IPv6[size];
            for (FormatStyle style : FormatStyle.values()) {
                setInstance(instances, style, false, false, false);
                setInstance(instances, style, false, false, true);
                setInstance(instances, style, false, true, false);
                setInstance(instances, style, false, true, true);
                setInstance(instances, style, true, false, false);
                setInstance(instances, style, true, false, true);
                setInstance(instances, style, true, true, false);
                setInstance(instances, style, true, true, true);
            }
            return instances;
        }

        private static void setInstance(IPv6[] instances, FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets) {
            instances[indexOfInstance(style, upperCase, withIPv4End, encloseInBrackets)] = new IPv6(style, upperCase, withIPv4End, encloseInBrackets);
        }

        private static IPv6 valueOf(FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets) {
            return INSTANCES[indexOfInstance(style, upperCase, withIPv4End, encloseInBrackets)];
        }

        private static int indexOfInstance(FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets) {
            return (encloseInBrackets ? 1 : 0)
                    | (withIPv4End ? 1 << 1 : 0)
                    | (upperCase ? 1 << 2 : 0)
                    | (style.ordinal() << 3);
        }

        private static final class Parser {

            private final CharSequence source;
            private final int end;
            private final boolean parseAll;

            private final IPv4.Parser ipv4Parser;

            private int index;
            private int errorIndex;

            private int hextetCount;
            private int zeroesSectionStart = IPv6Address.HEXTETS;

            private long highAddress = 0;
            private long lowAddress = 0;
            private long zeroesSectionHighAddress = 0;
            private long zeroesSectionLowAddress = 0;

            private Parser(CharSequence source, int start, int end, boolean parseAll) {
                this.source = source;
                this.end = end;
                this.parseAll = parseAll;

                // the index will be changed as necessary
                ipv4Parser = new IPv4.Parser(source, start, end, false);

                index = start;
                errorIndex = -1;
            }

            private boolean parse() {
                boolean requiresClosingBracket = parseOpeningBracket();
                return parseHigh()
                        && parseLow()
                        // parsePostZeroesSection will always return true, letting any error processing over to parseEnd
                        && parsePostZeroesSection()
                        && parseEnd(requiresClosingBracket);
            }

            // high-level parse methods - these update internal fields

            private boolean parseHigh() {
                long hshift = HSHIFT3;
                boolean colonRequired = false;
                for (int i = 0; i < IPv6Address.HEXTETS / 2; i++) {
                    if (parseZeroesSection()) {
                        return true;
                    }

                    long hextet = parseColonAndHextet(colonRequired);
                    if (hextet == -1) {
                        return false;
                    }

                    highAddress |= hextet << hshift;
                    hextetCount++;
                    hshift -= HSHIFT;

                    colonRequired = true;
                }
                return true;
            }

            private boolean parseLow() {
                if (zeroesSectionStart != IPv6Address.HEXTETS) {
                    // already found a consecutive section of zeroes, return true to let parsePostZeroesSection do the rest
                    return true;
                }

                long hshift = HSHIFT3;
                // read all but the last two hextets
                for (int i = 0; i < IPv6Address.HEXTETS / 2 - 2; i++) {
                    if (parseZeroesSection()) {
                        return true;
                    }

                    long hextet = parseColonAndHextet(true);
                    if (hextet == -1) {
                        return false;
                    }

                    lowAddress |= hextet << hshift;
                    hextetCount++;
                    hshift -= HSHIFT;
                }

                if (parseZeroesSection()) {
                    return true;
                }

                // 2 hextets remaining; first try to parse as IPv4
                if (tryParseIPv4(true)) {
                    return true;
                }

                // try to parse the remaining 2 hextets as hextets
                for (int i = IPv6Address.HEXTETS / 2 - 2; i < IPv6Address.HEXTETS / 2; i++) {
                    if (parseZeroesSection()) {
                        return true;
                    }

                    long hextet = parseColonAndHextet(true);
                    if (hextet == -1) {
                        return false;
                    }

                    lowAddress |= hextet << hshift;
                    hextetCount++;
                    hshift -= HSHIFT;
                }
                return true;
            }

            private boolean parsePostZeroesSection() {
                if (zeroesSectionStart == IPv6Address.HEXTETS) {
                    // didn't a consecutive section of zeroes, nothing needs to be done
                    return true;
                }

                if (hextetCount == IPv6Address.HEXTETS - 1) {
                    // only one section of zeroes omitted
                    return true;
                }

                // hextetCount cannot exceed IPv6Address.HEXTETS - 1

                boolean colonRequired = false;
                while (hextetCount < IPv6Address.HEXTETS - 2) {
                    // try to parse as IPv4 first
                    if (tryParseIPv4(colonRequired)) {
                        // tryParseIPv4 added the IPv4 to lowAddress; add two post zeroes section hextets to compensate
                        addPostZeroesSectionHextet(0);
                        addPostZeroesSectionHextet(0);
                        return true;
                    }

                    long hextet = tryParseColonAndHextet(colonRequired);
                    if (hextet == -1) {
                        return true;
                    }

                    addPostZeroesSectionHextet(hextet);

                    colonRequired = true;
                }

                // hextetCount >= IPv6Address.HEXTETS - 2, an IPv4 end is no longer allowed
                long hextet = tryParseColonAndHextet(colonRequired);
                if (hextet == -1) {
                    return true;
                }

                addPostZeroesSectionHextet(hextet);

                return true;
            }

            private boolean parseEnd(boolean requiresClosingBracket) {
                if (requiresClosingBracket && !parseClosingBracket()) {
                    errorIndex = Math.max(index, errorIndex);
                    return false;
                }
                if (parseAll && index != end) {
                    errorIndex = Math.max(index, errorIndex);
                    return false;
                }

                highAddress |= zeroesSectionHighAddress;
                lowAddress |= zeroesSectionLowAddress;

                return true;
            }

            // mid-level parse methods - these update internal fields

            private boolean parseZeroesSection() {
                if (parseDoubleColon()) {
                    zeroesSectionStart = hextetCount;
                    return true;
                }
                return false;
            }

            private int parseColonAndHextet(boolean colonRequired) {
                if (colonRequired && !parseColon()) {
                    errorIndex = Math.max(index, errorIndex);
                    return -1;
                }
                int hextet = parseHextet();
                if (hextet == -1) {
                    errorIndex = Math.max(index, errorIndex);
                    return -1;
                }
                return hextet;
            }

            private int tryParseColonAndHextet(boolean colonRequired) {
                int oldIndex = index;
                if (colonRequired && !parseColon()) {
                    return -1;
                }
                int hextet = parseHextet();
                if (hextet == -1) {
                    index = oldIndex;
                    return -1;
                }
                return hextet;
            }

            private boolean tryParseIPv4(boolean colonRequired) {
                int oldIndex = index;
                if (colonRequired && !parseColon()) {
                    return false;
                }

                ipv4Parser.address = 0;
                ipv4Parser.index = index;
                ipv4Parser.errorIndex = -1;
                if (ipv4Parser.parse()) {
                    lowAddress |= ipv4Parser.address & 0xFFFF_FFFFL;
                    index = ipv4Parser.index;
                    hextetCount += 2;
                    return true;
                }

                index = oldIndex;
                errorIndex = Math.max(ipv4Parser.errorIndex, errorIndex);
                return false;
            }

            private void addPostZeroesSectionHextet(long hextet) {
                zeroesSectionHighAddress <<= HSHIFT;
                zeroesSectionHighAddress |= (zeroesSectionLowAddress >> HSHIFT3) & HMASK;
                zeroesSectionLowAddress <<= HSHIFT;
                zeroesSectionLowAddress |= hextet;
                hextetCount++;
            }

            // low-level parse methods - these update only the index

            private boolean parseOpeningBracket() {
                if (index < end && source.charAt(index) == '[') {
                    index++;
                    return true;
                }
                return false;
            }

            private boolean parseClosingBracket() {
                if (index < end && source.charAt(index) == ']') {
                    index++;
                    return true;
                }
                return false;
            }

            private boolean parseDoubleColon() {
                if (index < end - 1 && source.charAt(index) == ':' && source.charAt(index + 1) == ':') {
                    index += 2;
                    return true;
                }
                return false;
            }

            private boolean parseColon() {
                if (index < end && source.charAt(index) == ':') {
                    index++;
                    return true;
                }
                return false;
            }

            private int parseHextet() {
                int hextet = 0;
                int chars;
                for (chars = 0; chars < 4 && index < end; chars++, index++) {
                    char c = source.charAt(index);
                    int d = Character.digit(c, 16);
                    if (d == -1) {
                        // not part of a hextet
                        break;
                    }
                    hextet <<= 4;
                    hextet |= d;
                }
                if (chars == 0) {
                    return -1;
                }
                return hextet;
            }
        }
    }

    private static final class AnyVersion extends IPAddressFormatter<IPAddress<?>> {

        private static final AnyVersion[] INSTANCES = createInstances();
        private static final AnyVersion DEFAULT_INSTANCE = valueOf(FormatStyle.SHORT, false, false, false);

        private final IPv4 ipv4;
        private final IPv6 ipv6;

        private AnyVersion(IPv4 ipv4, IPv6 ipv6) {
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
        }

        @Override
        public String format(IPAddress<?> address) {
            if (address instanceof IPv4Address) {
                return ipv4.format((IPv4Address) address);
            }
            if (address instanceof IPv6Address) {
                return ipv6.format((IPv6Address) address);
            }
            Objects.requireNonNull(address);
            throw new IllegalStateException("unsupported IP addres type: " + address.getClass()); //$NON-NLS-1$
        }

        @Override
        public <A extends Appendable> A append(IPAddress<?> address, A appendable) throws IOException {
            if (address instanceof IPv4Address) {
                return ipv4.append((IPv4Address) address, appendable);
            }
            if (address instanceof IPv6Address) {
                return ipv6.append((IPv6Address) address, appendable);
            }
            Objects.requireNonNull(address);
            throw new IllegalStateException("unsupported IP addres type: " + address.getClass()); //$NON-NLS-1$
        }

        @Override
        public String format(byte[] address) {
            switch (address.length) {
            case IPv4Address.BYTES:
                return ipv4.format(address);
            case IPv6Address.BYTES:
                return ipv6.format(address);
            default:
                throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
            }
        }

        @Override
        public <A extends Appendable> A append(byte[] address, A appendable) throws IOException {
            switch (address.length) {
            case IPv4Address.BYTES:
                return ipv4.append(address, appendable);
            case IPv6Address.BYTES:
                return ipv6.append(address, appendable);
            default:
                throw new IllegalArgumentException(Messages.IPAddress.invalidArraySize.get(address.length));
            }
        }

        @Override
        StringBuffer format(Object object, StringBuffer dest) {
            if (object instanceof IPAddress<?>) {
                return format((IPAddress<?>) object, dest);
            }
            if (object instanceof byte[]) {
                return format((byte[]) object, dest);
            }
            throw new IllegalArgumentException(Messages.IPAddressFormat.unformattableObject.get(object));
        }

        @Override
        IPAddress<?> valueOf(CharSequence address, int start, int end) {
            return valueOf(address, start, end, Messages.IPAddress.invalidIPAddress::get);
        }

        @Override
        IPAddress<?> valueOf(CharSequence address, int start, int end, Function<CharSequence, String> errorMessage) {
            return getFormatter(address, start, end).valueOf(address, start, end, errorMessage);
        }

        @Override
        public IPAddress<?> parse(CharSequence source, int start, int end) throws ParseException {
            return parse(source, start, end, Messages.IPAddress.parseError::get);
        }

        @Override
        IPAddress<?> parse(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            return getFormatter(source, start, end).parse(source, start, end, errorMessage);
        }

        @Override
        public IPAddress<?> parse(CharSequence source, ParsePosition position) {
            return getFormatter(source, position.getIndex(), source.length()).parse(source, position);
        }

        @Override
        @SuppressWarnings("unchecked")
        public Optional<IPAddress<?>> tryParse(CharSequence source, int start, int end) {
            return source == null ? Optional.empty() : (Optional<IPAddress<?>>) getFormatter(source, start, end).tryParse(source, start, end);
        }

        @Override
        public byte[] parseToBytes(CharSequence source, int start, int end) throws ParseException {
            return parseToBytes(source, start, end, Messages.IPAddress.parseError::get);
        }

        @Override
        byte[] parseToBytes(CharSequence source, int start, int end, Function<CharSequence, String> errorMessage) throws ParseException {
            return getFormatter(source, start, end).parseToBytes(source, start, end, errorMessage);
        }

        @Override
        public byte[] parseToBytes(CharSequence source, ParsePosition position) {
            return getFormatter(source, position.getIndex(), source.length()).parseToBytes(source, position);
        }

        @Override
        public Optional<byte[]> tryParseToBytes(CharSequence source, int start, int end) {
            return source == null ? Optional.empty() : getFormatter(source, start, end).tryParseToBytes(source, start, end);
        }

        @Override
        public IPAddressFormat<IPAddress<?>> asFormat() {
            int index = IPv6.indexOfInstance(ipv6.style, ipv6.upperCase, ipv6.withIPv4End, ipv6.encloseInBrackets);
            return AnyVersionFormat.INSTANCES[index];
        }

        @Override
        boolean isValid(CharSequence source, int start, int end) {
            return source != null && getFormatter(source, start, end).isValid(source, start, end);
        }

        @Override
        boolean testIfValid(CharSequence source, Predicate<? super IPAddress<?>> predicate) {
            return source != null && getFormatter(source, 0, source.length()).testIfValid(source, predicate);
        }

        private IPAddressFormatter<?> getFormatter(CharSequence source, int start, int end) {
            checkBounds(source, start, end);
            int firstDot = indexOf(source, '.', start, end);
            int firstColon = indexOf(source, ':', start, end);
            if (firstDot == -1 && firstColon == -1) {
                // parsing will fail anyway, doesn't matter which one to use
                return ipv6;
            }
            if (firstDot == -1) {
                // no dots but only colons, attempt IPv6
                return ipv6;
            }
            if (firstColon == -1) {
                // no colons but only dots, attempt IPv4
                return ipv4;
            }
            // IPv4 does not support colons, so if there is a colon before a dot, attempt IPv6
            return firstColon < firstDot ? ipv6 : ipv4;
        }

        private int indexOf(CharSequence source, char c, int start, int end) {
            for (int i = start, length = end; i < length; i++) {
                if (c == source.charAt(i)) {
                    return i;
                }
            }
            return -1;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormatter.class.getName() + "#anyVersion"
                    + "[style=" + ipv6.style
                    + ",upperCase=" + ipv6.upperCase
                    + ",withIPv4End=" + ipv6.withIPv4End
                    + ",encloseInBrackets=" + ipv6.encloseInBrackets
                    + "]";
        }

        private static AnyVersion[] createInstances() {
            return Arrays.stream(IPv6.INSTANCES)
                    .map(ipv6 -> new AnyVersion(IPv4.INSTANCE, ipv6))
                    .toArray(AnyVersion[]::new);
        }

        private static AnyVersion valueOf(FormatStyle style, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets) {
            return INSTANCES[IPv6.indexOfInstance(style, upperCase, withIPv4End, encloseInBrackets)];
        }
    }

    private enum FormatStyle {
        SHORT {
            @Override
            boolean append(long highAddress, long lowAddress, boolean upperCase, int formatEnd, Appendable dest) throws IOException {
                boolean endsWithColon = false;

                int longestZeroesSection = findLongestZeroesSection(highAddress, lowAddress, formatEnd);
                if (longestZeroesSection == 0) {
                    // no consecutive sections of zeroes
                    appendMediumHextet(hextet(highAddress, lowAddress, 0), upperCase, dest);
                    for (int i = 1; i < formatEnd; i++) {
                        dest.append(':');
                        appendMediumHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                    }
                } else {
                    int zeroesSectionStart = (longestZeroesSection >> 8) & 0xFF;
                    int zeroesSectionEnd = longestZeroesSection & 0xFF;

                    if (zeroesSectionStart == 0) {
                        // either ::X or ::
                        dest.append(':');
                        endsWithColon = true;
                        if (zeroesSectionEnd == formatEnd) {
                            dest.append(':');
                        } else {
                            for (int i = zeroesSectionEnd; i < formatEnd; i++) {
                                dest.append(':');
                                appendMediumHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                                endsWithColon = false;
                            }
                        }
                    } else {
                        // either X:: or X::Y
                        for (int i = 0; i < zeroesSectionStart; i++) {
                            appendMediumHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                            dest.append(':');
                            endsWithColon = true;
                        }
                        if (zeroesSectionEnd == formatEnd) {
                            dest.append(':');
                            endsWithColon = true;
                        } else {
                            for (int i = zeroesSectionEnd; i < formatEnd; i++) {
                                dest.append(':');
                                appendMediumHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                                endsWithColon = false;
                            }
                        }
                    }
                }
                return endsWithColon;
            }

            int findLongestZeroesSection(long highAddress, long lowAddress, int formatEnd) {
                int zeroesSectionStart = 0;
                int zeroesSectionEnd = 0;
                int zeroesSectionSize = 0;
                for (int i = 0; i < formatEnd; i++) {
                    int hextet = hextet(highAddress, lowAddress, i);
                    if (hextet == 0) {
                        int index = i;
                        int count = 0;
                        for ( ; i < formatEnd; i++, count++) {
                            hextet = hextet(highAddress, lowAddress, i);
                            if (hextet != 0) {
                                break;
                            }
                        }
                        if (count > zeroesSectionSize) {
                            zeroesSectionStart = index;
                            zeroesSectionEnd = index + count;
                            zeroesSectionSize = count;
                        }
                    }
                }
                return zeroesSectionStart << 8 | zeroesSectionEnd;
            }
        },

        MEDIUM {
            @Override
            boolean append(long highAddress, long lowAddress, boolean upperCase, int formatEnd, Appendable dest) throws IOException {
                appendMediumHextet(hextet(highAddress, lowAddress, 0), upperCase, dest);
                for (int i = 1; i < formatEnd; i++) {
                    dest.append(':');
                    appendMediumHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                }
                return false;
            }
        },

        LONG {
            @Override
            boolean append(long highAddress, long lowAddress, boolean upperCase, int formatEnd, Appendable dest) throws IOException {
                appendLongHextet(hextet(highAddress, lowAddress, 0), upperCase, dest);
                for (int i = 1; i < formatEnd; i++) {
                    dest.append(':');
                    appendLongHextet(hextet(highAddress, lowAddress, i), upperCase, dest);
                }
                return false;
            }
        },
        ;

        void append(IPv6Address address, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets, Appendable dest) throws IOException {
            append(address.highAddress, address.lowAddress, upperCase, withIPv4End, encloseInBrackets, dest);
        }

        void append(byte[] address, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets, Appendable dest) throws IOException {
            long highAddress = addressToHighAddress(address);
            long lowAddress = addressToLowAddress(address);
            append(highAddress, lowAddress, upperCase, withIPv4End, encloseInBrackets, dest);
        }

        private void append(long highAddress, long lowAddress, boolean upperCase, boolean withIPv4End, boolean encloseInBrackets, Appendable dest)
                throws IOException {

            int formatEnd = IPv6Address.HEXTETS - (withIPv4End ? 2 : 0);
            if (encloseInBrackets) {
                dest.append('[');
            }
            boolean endsWithColon = append(highAddress, lowAddress, upperCase, formatEnd, dest);
            if (withIPv4End) {
                appendIPv4(lowAddress, dest, endsWithColon);
            }
            if (encloseInBrackets) {
                dest.append(']');
            }
        }

        abstract boolean append(long highAddress, long lowAddress, boolean upperCase, int formatEnd, Appendable dest) throws IOException;

        private void appendIPv4(long lowAddress, Appendable dest, boolean endsWithColon) throws IOException {
            // add a : if needed
            if (!endsWithColon) {
                dest.append(':');
            }
            IPv4.INSTANCE.append((int) lowAddress, dest);
        }

        int hextet(long highAddress, long lowAddress, int index) {
            return index < 4
                    ? (int) ((highAddress >> ((3 - index) * HSHIFT)) & HMASK)
                    : (int) ((lowAddress >> ((7 - index) * HSHIFT)) & HMASK);
        }

        void appendMediumHextet(int hextet, boolean upperCase, Appendable dest) throws IOException {
            boolean added = false;

            added = appendChar((hextet >> 12) & 0xF, upperCase, dest, added);
            added = appendChar((hextet >> 8) & 0xF, upperCase, dest, added);
            appendChar((hextet >> 4) & 0xF, upperCase, dest, added);
            appendChar(hextet & 0xF, upperCase, dest, true);
        }

        void appendLongHextet(int hextet, boolean upperCase, Appendable dest) throws IOException {
            appendChar((hextet >> 12) & 0xF, upperCase, dest, true);
            appendChar((hextet >> 8) & 0xF, upperCase, dest, true);
            appendChar((hextet >> 4) & 0xF, upperCase, dest, true);
            appendChar(hextet & 0xF, upperCase, dest, true);
        }

        private boolean appendChar(int i, boolean upperCase, Appendable dest, boolean addIfZero) throws IOException {
            if (i != 0 || addIfZero) {
                char c = Character.forDigit(i, 16);
                c = upperCase ? Character.toUpperCase(c) : Character.toLowerCase(c);
                dest.append(c);
                return true;
            }
            return false;
        }
    }

    private static final class IPv4Format extends IPAddressFormat<IPv4Address> {

        private static final long serialVersionUID = -7978163144639634602L;

        private static final IPv4Format INSTANCE = new IPv4Format();

        @Override
        IPAddressFormatter<IPv4Address> formatter() {
            return IPv4.INSTANCE;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormat.class.getName() + "#IPv4";
        }

        private Object readResolve() {
            return INSTANCE;
        }
    }

    private static final class IPv6Format extends IPAddressFormat<IPv6Address> {

        private static final long serialVersionUID = 8686933570972695431L;

        private static final IPv6Format[] INSTANCES = createInstances();

        private final IPv6 formatter;
        private final int index;

        private IPv6Format(IPv6 formatter, int index) {
            this.formatter = formatter;
            this.index = index;
        }

        @Override
        IPAddressFormatter<IPv6Address> formatter() {
            return formatter;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormat.class.getName() + "#IPv6"
                    + "[style=" + formatter.style
                    + ",upperCase=" + formatter.upperCase
                    + ",withIPv4End=" + formatter.withIPv4End
                    + ",encloseInBrackets=" + formatter.encloseInBrackets
                    + "]";
        }

        private static IPv6Format[] createInstances() {
            IPv6Format[] instances = new IPv6Format[IPv6.INSTANCES.length];
            for (int i = 0; i < IPv6.INSTANCES.length; i++) {
                instances[i] = new IPv6Format(IPv6.INSTANCES[i], i);
            }
            return instances;
        }

        private Object writeReplace() {
            return new Proxy(this);
        }

        private static final class Proxy implements Serializable {

            private static final long serialVersionUID = -7812395775589349986L;

            private final int index;

            private Proxy(IPv6Format instance) {
                index = instance.index;
            }

            private Object readResolve() {
                return INSTANCES[index];
            }
        }
    }

    private static final class AnyVersionFormat extends IPAddressFormat<IPAddress<?>> {

        private static final long serialVersionUID = -8878877461559168142L;

        private static final AnyVersionFormat[] INSTANCES = createInstances();

        private final AnyVersion formatter;
        private final int index;

        private AnyVersionFormat(AnyVersion formatter, int index) {
            this.formatter = formatter;
            this.index = index;
        }

        @Override
        IPAddressFormatter<IPAddress<?>> formatter() {
            return formatter;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            return IPAddressFormat.class.getName() + "#anyVersion"
                    + "[style=" + formatter.ipv6.style
                    + ",upperCase=" + formatter.ipv6.upperCase
                    + ",withIPv4End=" + formatter.ipv6.withIPv4End
                    + ",encloseInBrackets=" + formatter.ipv6.encloseInBrackets
                    + "]";
        }

        private static AnyVersionFormat[] createInstances() {
            AnyVersionFormat[] instances = new AnyVersionFormat[AnyVersion.INSTANCES.length];
            for (int i = 0; i < AnyVersion.INSTANCES.length; i++) {
                instances[i] = new AnyVersionFormat(AnyVersion.INSTANCES[i], i);
            }
            return instances;
        }

        private Object writeReplace() {
            return new Proxy(this);
        }

        private static final class Proxy implements Serializable {

            private static final long serialVersionUID = -7051203599374151532L;

            private final int index;

            private Proxy(AnyVersionFormat instance) {
                index = instance.index;
            }

            private Object readResolve() {
                return INSTANCES[index];
            }
        }
    }
}
