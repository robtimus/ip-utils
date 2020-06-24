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
import static org.junit.jupiter.params.provider.Arguments.arguments;
import java.util.Spliterator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class AbstractIPv4RangeTest {

    @ParameterizedTest(name = "[{0}...{1}]: {2}")
    @MethodSource
    @DisplayName("size")
    void testSize(IPv4Address from, IPv4Address to, int expectedSize) {
        IPv4Range ipRange = new TestRange(from, to);
        assertEquals(expectedSize, ipRange.size());
        assertEquals(expectedSize, ipRange.size());
    }

    static Arguments[] testSize() {
        return new Arguments[] {
                arguments(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE, Integer.MAX_VALUE),
                arguments(new IPv4Address(0), new IPv4Address(Integer.MAX_VALUE), Integer.MAX_VALUE),
                arguments(new IPv4Address(Integer.MAX_VALUE - 1000), new IPv4Address(Integer.MAX_VALUE), 1001),
        };
    }

    @Test
    @DisplayName("spliterator")
    void testSpliterator() {
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
