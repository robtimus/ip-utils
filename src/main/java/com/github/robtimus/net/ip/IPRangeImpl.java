/*
 * IPRangeImpl.java
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

final class IPRangeImpl {

    private IPRangeImpl() {
        throw new IllegalStateException("cannot create instances of " + getClass().getName()); //$NON-NLS-1$
    }

    static final class IPv4 extends AbstractIPv4Range {

        static final IPv4Range ALL = new IPRangeImpl.IPv4(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE);

        private final IPv4Address from;
        private final IPv4Address to;

        private String stringValue;

        IPv4(IPv4Address from, IPv4Address to) {
            this.from = from;
            this.to = to;
        }

        @Override
        public IPv4Address from() {
            return from;
        }

        @Override
        public IPv4Address to() {
            return to;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            if (stringValue == null) {
                stringValue = "[" + from + "..." + to + "]";
            }
            return stringValue;
        }
    }

    static final class IPv6 extends AbstractIPv6Range {

        static final IPv6Range ALL = new IPRangeImpl.IPv6(IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE);

        private final IPv6Address from;
        private final IPv6Address to;

        private String stringValue;

        IPv6(IPv6Address from, IPv6Address to) {
            this.from = from;
            this.to = to;
        }

        @Override
        public IPv6Address from() {
            return from;
        }

        @Override
        public IPv6Address to() {
            return to;
        }

        @Override
        @SuppressWarnings("nls")
        public String toString() {
            if (stringValue == null) {
                stringValue = "[" + from + "..." + to + "]";
            }
            return stringValue;
        }
    }
}
