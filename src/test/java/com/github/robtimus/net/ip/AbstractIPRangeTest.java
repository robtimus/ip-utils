/*
 * AbstractIPRangeTest.java
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
import static org.junit.jupiter.params.provider.Arguments.arguments;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings({ "javadoc", "nls" })
public class AbstractIPRangeTest {

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("equals")
    public void testEquals(IPRange<?> ipRange, Object object, boolean expectEquals) {
        BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        equalsCheck.accept(ipRange, object);
    }

    static Arguments[] testEquals() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        return new Arguments[] {
                arguments(ipRange, null, false),
                arguments(ipRange, "foo", false),
                arguments(ipRange, address.to(IPv4Address.MAX_VALUE), false),
                arguments(ipRange, ipRange, true),
                arguments(ipRange, address.previous().to(address.next()), true),
                arguments(ipRange, new IPRangeImpl.IPv4(address.previous(), address.next()), true),
                arguments(ipRange, address.previous().to(address), false),
                arguments(ipRange, address.to(address.next()), false),
        };
    }

    @Test
    @DisplayName("hashCode")
    public void testHashCode() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertEquals(ipRange.hashCode(), ipRange.hashCode());
        assertEquals(address.previous().hashCode() ^ address.next().hashCode(), ipRange.hashCode());
    }

    private static final class TestRange extends AbstractIPRange<IPv4Address> {

        private final IPv4Address address;

        private TestRange(IPv4Address address) {
            this.address = address;
        }

        @Override
        public IPv4Address from() {
            return address.previous();
        }

        @Override
        public IPv4Address to() {
            return address.next();
        }

        @Override
        public int size() {
            return 3;
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + "[" + from() + "..." + to() + "]";
        }
    }
}
