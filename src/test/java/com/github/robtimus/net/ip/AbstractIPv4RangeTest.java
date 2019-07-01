/*
 * AbstractIPv4RangeTest.java
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
public class AbstractIPv4RangeTest {

    @TestFactory
    public DynamicTest[] testSize() {
        return new DynamicTest[] {
                testSize(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE, Integer.MAX_VALUE),
                testSize(new IPv4Address(0), new IPv4Address(Integer.MAX_VALUE), Integer.MAX_VALUE),
                testSize(new IPv4Address(Integer.MAX_VALUE - 1000), new IPv4Address(Integer.MAX_VALUE), 1001),
        };
    }

    private DynamicTest testSize(IPv4Address from, IPv4Address to, int expectedSize) {
        IPv4Range ipRange = new TestRange(from, to);
        return dynamicTest(String.format("[%s...%s]: %d", from, to, expectedSize), () -> {
            assertEquals(expectedSize, ipRange.size());
            assertEquals(expectedSize, ipRange.size());
        });
    }

    @Test
    public void testSpliterator() {
        IPv4Range ipRange = new TestRange(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE);
        Spliterator<?> spliterator = ipRange.spliterator();
        // IPv4RangeSpliterator has its own tests
        assertEquals(IPv4RangeSpliterator.class, spliterator.getClass());
    }

    private static final class TestRange extends AbstractIPv4Range {

        private final IPv4Address from;
        private final IPv4Address to;

        private TestRange(IPv4Address from, IPv4Address to) {
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
    }
}
