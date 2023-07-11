/*
 * SingletonIPRangeTest.java
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.function.Consumer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("nls")
class SingletonIPRangeTest {

    @Test
    @DisplayName("from and to")
    void testFromAndTo() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertSame(address, ipRange.from());
        assertSame(address, ipRange.to());
    }

    @Test
    @DisplayName("size")
    void testSize() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals(1, ipRange.size());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("contains")
    <I extends IPAddress<I>> void testContains(IPRange<I> ipRange, I address, boolean expected) {
        assertEquals(expected, ipRange.contains(address));
        assertEquals(expected, ipRange.contains((Object) address));
    }

    static Arguments[] testContains() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPv4Range ipRange = new SingletonIPRange.IPv4(address);
        return new Arguments[] {
                arguments(ipRange, address, true),
                arguments(ipRange, address.previous(), false),
                arguments(ipRange, address.next(), false),
                arguments(ipRange, null, false),
                arguments(ipRange, IPv6Address.LOCALHOST, false),
        };
    }

    @Test
    @DisplayName("iterator")
    void testIterator() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new SingletonIPRange.IPv4(address);
        Iterator<IPv4Address> iterator = ipRange.iterator();
        assertTrue(iterator.hasNext());
        assertSame(address, iterator.next());
        assertFalse(iterator.hasNext());
        assertThrows(NoSuchElementException.class, () -> iterator.next());
    }

    @TestFactory
    @DisplayName("toArray")
    DynamicTest[] testToArray() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        return new DynamicTest[] {
                dynamicTest("no array", () -> {
                    Object[] array = ipRange.toArray();
                    assertEquals(Object[].class, array.getClass());
                    assertArrayEquals(new Object[] { address }, array);
                }),
                dynamicTest("empty array", () -> {
                    Object[] a = new IPv4Address[0];
                    Object[] array = ipRange.toArray(a);
                    assertNotSame(a, array);
                    assertEquals(IPv4Address[].class, array.getClass());
                    assertArrayEquals(new IPv4Address[] { address }, array);
                }),
                dynamicTest("array of same size", () -> {
                    Object[] a = new IPv4Address[1];
                    Object[] array = ipRange.toArray(a);
                    assertSame(a, array);
                    assertArrayEquals(new IPv4Address[] { address }, array);
                }),
                dynamicTest("array of larger size", () -> {
                    Object[] a = new IPv4Address[] { null, IPv4Address.MAX_VALUE };
                    Object[] array = ipRange.toArray(a);
                    assertSame(a, array);
                    assertArrayEquals(new IPv4Address[] { address, null }, array);
                }),
        };
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("containsAll")
    void testContainsAll(IPRange<?> ipRange, Collection<?> c, boolean expected) {
        assertEquals(expected, ipRange.containsAll(c));
    }

    static Arguments[] testContainsAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        return new Arguments[] {
                arguments(ipRange, Collections.emptyList(), true),
                arguments(ipRange, ipRange, true),
                arguments(ipRange, Collections.singleton(address), true),
                arguments(ipRange, Arrays.asList(address, address), true),
                arguments(ipRange, Arrays.asList(address, address.next()), false),
                arguments(ipRange, Arrays.asList(address.previous(), address), false),
        };
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    @DisplayName("equals")
    void testEquals(IPRange<?> ipRange, Object object, boolean expected) {
        assertEquals(expected, ipRange.equals(object));
    }

    static Arguments[] testEquals() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        return new Arguments[] {
                arguments(ipRange, null, false),
                arguments(ipRange, "foo", false),
                arguments(ipRange, address.to(IPv4Address.MAX_VALUE), false),
                arguments(ipRange, ipRange, true),
                arguments(ipRange, address.to(address), true),
                arguments(ipRange, new IPRangeImpl.IPv4(address, address), true),
                arguments(ipRange, address.previous().to(address), false),
                arguments(ipRange, address.to(address.next()), false),
        };
    }

    @Test
    @DisplayName("hashCode")
    void testHashCode() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals(ipRange.hashCode(), ipRange.hashCode());
        assertEquals(address.hashCode() * 31 + address.hashCode(), ipRange.hashCode());
        assertNotEquals(0, ipRange.hashCode());
    }

    @Test
    @DisplayName("toString")
    void testToString() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals("[127.0.0.1]", ipRange.toString());
        // test caching
        assertSame(ipRange.toString(), ipRange.toString());
    }

    @Test
    @DisplayName("forEach")
    void testForEach() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        @SuppressWarnings("unchecked")
        Consumer<Object> action = mock(Consumer.class);
        ipRange.forEach(action);
        verify(action).accept(address);
        verifyNoMoreInteractions(action);
    }

    @Test
    @DisplayName("spliterator")
    @SuppressWarnings("unchecked")
    void testSpliterator() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);

        Spliterator<?> spliterator = ipRange.spliterator();
        assertTrue(spliterator.hasCharacteristics(Spliterator.ORDERED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.DISTINCT));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SORTED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SIZED));
        assertTrue(spliterator.hasCharacteristics(Spliterator.NONNULL));
        assertTrue(spliterator.hasCharacteristics(Spliterator.IMMUTABLE));
        assertFalse(spliterator.hasCharacteristics(Spliterator.CONCURRENT));
        assertTrue(spliterator.hasCharacteristics(Spliterator.SUBSIZED));
        assertNull(spliterator.getComparator());

        spliterator = ipRange.spliterator();
        Consumer<Object> action = mock(Consumer.class);
        assertTrue(spliterator.tryAdvance(action));
        assertFalse(spliterator.tryAdvance(action));
        verify(action).accept(address);
        verifyNoMoreInteractions(action);

        spliterator = ipRange.spliterator();
        action = mock(Consumer.class);
        spliterator.forEachRemaining(action);
        spliterator.forEachRemaining(action);
        verify(action).accept(address);
        verifyNoMoreInteractions(action);

        spliterator = ipRange.spliterator();
        assertNull(spliterator.trySplit());

        spliterator = ipRange.spliterator();
        assertEquals(1, spliterator.estimateSize());
        assertEquals(1, spliterator.getExactSizeIfKnown());
        spliterator.tryAdvance(action);
        assertEquals(0, spliterator.estimateSize());
        assertEquals(0, spliterator.getExactSizeIfKnown());
    }
}
