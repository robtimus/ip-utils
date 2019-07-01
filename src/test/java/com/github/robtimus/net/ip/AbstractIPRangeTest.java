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
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class AbstractIPRangeTest {

    @TestFactory
    public DynamicTest[] testEquals() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        return new DynamicTest[] {
                testEquals(ipRange, null, false),
                testEquals(ipRange, "foo", false),
                testEquals(ipRange, address.to(IPv4Address.MAX_VALUE), false),
                testEquals(ipRange, ipRange, true),
                testEquals(ipRange, address.previous().to(address.next()), true),
                testEquals(ipRange, new IPRangeImpl.IPv4(address.previous(), address.next()), true),
                testEquals(ipRange, address.previous().to(address), false),
                testEquals(ipRange, address.to(address.next()), false),
        };
    }

    private DynamicTest testEquals(IPRange<?> ipRange, Object object, boolean expectEquals) {
        BiConsumer<Object, Object> equalsCheck = expectEquals ? Assertions::assertEquals : Assertions::assertNotEquals;
        return dynamicTest(String.valueOf(object), () -> equalsCheck.accept(ipRange, object));
    }

    @Test
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
