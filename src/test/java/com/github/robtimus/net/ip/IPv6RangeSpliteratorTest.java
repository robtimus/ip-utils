/*
 * IPv6RangeSpliteratorTest.java
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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings("javadoc")
public class IPv6RangeSpliteratorTest {

    @Test
    public void testTrySplit() {
        IPv6RangeSpliterator spliterator = new IPv6RangeSpliterator(IPv6Address.MIN_VALUE.to(IPv6Address.MAX_VALUE));

        IPv6RangeSpliterator split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv6Address.MIN_VALUE, split.current);
        assertEquals(IPv6Address.valueOf(0x7FFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFEL), split.to);
        assertEquals(IPv6Address.valueOf(0x7FFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL), spliterator.current);
        assertEquals(IPv6Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv6Address.valueOf(0x7FFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL), split.current);
        assertEquals(IPv6Address.valueOf(0xBFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFEL), split.to);
        assertEquals(IPv6Address.valueOf(0xBFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL), spliterator.current);
        assertEquals(IPv6Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv6Address.valueOf(0xBFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL), split.current);
        assertEquals(IPv6Address.valueOf(0xDFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFEL), split.to);
        assertEquals(IPv6Address.valueOf(0xDFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL), spliterator.current);
        assertEquals(IPv6Address.MAX_VALUE, spliterator.to);

        spliterator = new IPv6RangeSpliterator(IPv6Address.MAX_VALUE.previous().previous().to(IPv6Address.MAX_VALUE));

        split = spliterator.trySplit();
        assertNotNull(split);
        assertEquals(IPv6Address.MAX_VALUE.previous().previous(), split.current);
        assertEquals(IPv6Address.MAX_VALUE.previous().previous(), split.to);
        assertEquals(IPv6Address.MAX_VALUE.previous(), spliterator.current);
        assertEquals(IPv6Address.MAX_VALUE, spliterator.to);

        split = spliterator.trySplit();
        assertNull(split);

        spliterator = new IPv6RangeSpliterator(IPv6Address.MAX_VALUE.previous().previous().to(IPv6Address.MAX_VALUE));
        spliterator.tryAdvance(ip -> { /* nothing */ });
        spliterator.tryAdvance(ip -> { /* nothing */ });
        spliterator.tryAdvance(ip -> { /* nothing */ });
        split = spliterator.trySplit();
        assertNull(split);
    }

    @TestFactory
    public DynamicTest[] testEstimateSize() {
        return new DynamicTest[] {
                testEstimateSize(IPv6Address.MIN_VALUE.to(IPv6Address.MAX_VALUE), spliterator -> {
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.MIN_VALUE.to(IPv6Address.valueOf(0, IPv6Address.MAX_LOW_ADDRESS)), spliterator -> {
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.MIN_VALUE.to(IPv6Address.valueOf(0, Long.MAX_VALUE)), spliterator -> {
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE - 1, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.MIN_VALUE.to(IPv6Address.valueOf(1, 0)), spliterator -> {
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.valueOf(0, IPv6Address.MAX_LOW_ADDRESS).to(IPv6Address.valueOf(1, IPv6Address.MAX_LOW_ADDRESS)),
                        spliterator -> {
                            assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                            spliterator.tryAdvance(ip -> { /* nothing */ });
                            assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                        }),
                testEstimateSize(IPv6Address.valueOf(0, IPv6Address.MAX_LOW_ADDRESS - Long.MAX_VALUE).to(IPv6Address.valueOf(1, Long.MAX_VALUE)),
                        spliterator -> {
                            assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                            spliterator.tryAdvance(ip -> { /* nothing */ });
                            assertEquals(Long.MAX_VALUE, spliterator.estimateSize());
                        }),
                testEstimateSize(IPv6Address.valueOf(0, IPv6Address.MAX_LOW_ADDRESS).to(IPv6Address.valueOf(1, 0)), spliterator -> {
                    assertEquals(2, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(1, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(0, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.LOCALHOST.asRange(), spliterator -> {
                    assertEquals(1, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(0, spliterator.estimateSize());
                }),
                testEstimateSize(IPv6Address.MAX_VALUE.asRange(), spliterator -> {
                    assertEquals(1, spliterator.estimateSize());
                    spliterator.tryAdvance(ip -> { /* nothing */ });
                    assertEquals(0, spliterator.estimateSize());
                }),
        };
    }

    private DynamicTest testEstimateSize(IPRange<IPv6Address> ipRange, Consumer<IPv6RangeSpliterator> test) {
        return dynamicTest(ipRange.toString(), () -> test.accept(new IPv6RangeSpliterator(ipRange)));
    }

    @TestFactory
    public DynamicTest[] testCharacteristics() {
        return new DynamicTest[] {
                testCharacteristics(IPv6Address.MIN_VALUE.to(IPv6Address.MAX_VALUE), false),
                testCharacteristics(IPv6Address.MIN_VALUE.to(IPv6Address.valueOf(0, Long.MAX_VALUE - 1)), false),
                testCharacteristics(IPv6Address.MIN_VALUE.to(IPv6Address.valueOf(0, Long.MAX_VALUE - 2)), true),
        };
    }

    private DynamicTest testCharacteristics(IPRange<IPv6Address> ipRange, boolean sized) {
        return dynamicTest(ipRange.toString(), () -> {
            IPv6RangeSpliterator spliterator = new IPv6RangeSpliterator(ipRange);
            assertTrue(spliterator.hasCharacteristics(Spliterator.ORDERED));
            assertTrue(spliterator.hasCharacteristics(Spliterator.DISTINCT));
            assertTrue(spliterator.hasCharacteristics(Spliterator.SORTED));
            assertEquals(sized, spliterator.hasCharacteristics(Spliterator.SIZED));
            assertTrue(spliterator.hasCharacteristics(Spliterator.NONNULL));
            assertTrue(spliterator.hasCharacteristics(Spliterator.IMMUTABLE));
            assertFalse(spliterator.hasCharacteristics(Spliterator.CONCURRENT));
            assertEquals(sized, spliterator.hasCharacteristics(Spliterator.SUBSIZED));
        });
    }
}
