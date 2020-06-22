/*
 * IPv4RangeSpliteratorTest.java
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import java.util.Spliterator;
import java.util.function.Consumer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings("javadoc")
public class IPv4RangeSpliteratorTest {

    @Test
    @DisplayName("trySplit")
    public void testTrySplit() {
        IPv4RangeSpliterator spliterator = new IPv4RangeSpliterator(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE);

        IPv4RangeSpliterator split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv4Address.MIN_VALUE, split.current);
        assertEquals(IPv4Address.valueOf(0x7FFF_FFFE), split.to);
        assertEquals(IPv4Address.valueOf(0x7FFF_FFFF), spliterator.current);
        assertEquals(IPv4Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv4Address.valueOf(0x7FFF_FFFF), split.current);
        assertEquals(IPv4Address.valueOf(0xBFFF_FFFE), split.to);
        assertEquals(IPv4Address.valueOf(0xBFFF_FFFF), spliterator.current);
        assertEquals(IPv4Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv4Address.valueOf(0xBFFF_FFFF), split.current);
        assertEquals(IPv4Address.valueOf(0xDFFF_FFFE), split.to);
        assertEquals(IPv4Address.valueOf(0xDFFF_FFFF), spliterator.current);
        assertEquals(IPv4Address.MAX_VALUE, spliterator.to);

        spliterator = new IPv4RangeSpliterator(IPv4Address.MAX_VALUE.previous().previous(), IPv4Address.MAX_VALUE);

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv4Address.MAX_VALUE.previous().previous(), split.current);
        assertEquals(IPv4Address.MAX_VALUE.previous().previous(), split.to);
        assertEquals(IPv4Address.MAX_VALUE.previous(), spliterator.current);
        assertEquals(IPv4Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNull(split);

        spliterator = new IPv4RangeSpliterator(IPv4Address.MAX_VALUE.previous().previous(), IPv4Address.MAX_VALUE);
        spliterator.tryAdvance(ip -> { /* nothing */ });
        spliterator.tryAdvance(ip -> { /* nothing */ });
        spliterator.tryAdvance(ip -> { /* nothing */ });
        split = spliterator.trySplit();
        assertNull(split);
    }

    @TestFactory
    @DisplayName("estimateSize")
    public DynamicTest[] testEstimateSize() {
        return new DynamicTest[] {
                testEstimateSize(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE, spliterator -> {
                    long remaining = 1L << 32L;
                    assertEquals(remaining--, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(remaining--, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(remaining, spliterator.estimateSize());
                }),
                testEstimateSize(IPv4Address.LOCALHOST, IPv4Address.LOCALHOST, spliterator -> {
                    assertEquals(1, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(0, spliterator.estimateSize());
                }),
                testEstimateSize(IPv4Address.MAX_VALUE, IPv4Address.MAX_VALUE, spliterator -> {
                    assertEquals(1, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(0, spliterator.estimateSize());
                }),
        };
    }

    private DynamicTest testEstimateSize(IPv4Address from, IPv4Address to, Consumer<IPv4RangeSpliterator> test) {
        return testEstimateSize(from.to(to), test);
    }

    private DynamicTest testEstimateSize(IPRange<IPv4Address> ipRange, Consumer<IPv4RangeSpliterator> test) {
        return dynamicTest(ipRange.toString(), () -> test.accept(new IPv4RangeSpliterator(ipRange)));
    }

    @Test
    @DisplayName("characteristics")
    public void testCharacteristics() {
        IPv4RangeSpliterator spliterator = new IPv4RangeSpliterator(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE);
        assertTrue(spliterator.hasCharacteristics(Spliterator.ORDERED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.DISTINCT));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SORTED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SIZED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.NONNULL));
        assertTrue(spliterator.hasCharacteristics(Spliterator.IMMUTABLE));
        assertFalse(spliterator.hasCharacteristics(Spliterator.CONCURRENT));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SUBSIZED));
    }
}
