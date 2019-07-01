/*
 * AbstractIPv6RangeTest.java
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
import java.util.Spliterator;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class AbstractIPv6RangeTest {

    @TestFactory
    public DynamicTest[] testSize() {
        return new DynamicTest[] {
                // same high address
                testSize(new IPv6Address(1000L, 0L), new IPv6Address(1000L, Long.MAX_VALUE), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MIN_LOW_ADDRESS), new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, 0L), new IPv6Address(1000L, Integer.MAX_VALUE), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, Long.MAX_VALUE - 1000L), new IPv6Address(1000L, Long.MAX_VALUE), 1001),

                // difference of 1 in high addresses
                testSize(new IPv6Address(1000L, 0L), new IPv6Address(1001L, Long.MAX_VALUE), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, 0L), 2),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS - Integer.MAX_VALUE), new IPv6Address(1001L, 0L), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS - 1000L), new IPv6Address(1001L, 1000L), 2002),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, IPv6Address.MAX_LOW_ADDRESS), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, Integer.MAX_VALUE), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, Integer.MAX_VALUE - 1), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, Integer.MAX_VALUE - 2), Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1001L, Integer.MAX_VALUE - 3), Integer.MAX_VALUE - 1),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS - 1000L), new IPv6Address(1001L, Integer.MAX_VALUE - 1000L),
                        Integer.MAX_VALUE),

                // difference > 1 in high addresses
                testSize(IPv6Address.MIN_VALUE, IPv6Address.MAX_VALUE, Integer.MAX_VALUE),
                testSize(new IPv6Address(1000L, IPv6Address.MAX_LOW_ADDRESS), new IPv6Address(1002L, 0), Integer.MAX_VALUE),
        };
    }

    private DynamicTest testSize(IPv6Address from, IPv6Address to, int expectedSize) {
        IPv6Range ipRange = new TestRange(from, to);
        return dynamicTest(String.format("[%s...%s]: %d", from, to, expectedSize), () -> {
            assertEquals(expectedSize, ipRange.size());
            assertEquals(expectedSize, ipRange.size());
        });
    }

    @Test
    public void testSpliterator() {
        IPv6Range ipRange = new AbstractIPv6Range() {
            @Override
            public IPv6Address from() {
                return IPv6Address.MIN_VALUE;
            }

            @Override
            public IPv6Address to() {
                return IPv6Address.MAX_VALUE;
            }
        };
        Spliterator<?> spliterator = ipRange.spliterator();
        // IPv6RangeSpliterator has its own tests
        assertEquals(IPv6RangeSpliterator.class, spliterator.getClass());
    }

    private static final class TestRange extends AbstractIPv6Range {

        private final IPv6Address from;
        private final IPv6Address to;

        private TestRange(IPv6Address from, IPv6Address to) {
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
    }
}
