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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class SingletonIPRangeTest {

    @Test
    public void testFromAndTo() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertSame(address, ipRange.from());
        assertSame(address, ipRange.to());
    }

    @Test
    public void testSize() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals(1, ipRange.size());
    }

    @TestFactory
    public DynamicTest[] testContains() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPv4Range ipRange = new SingletonIPRange.IPv4(address);
        return new DynamicTest[] {
                testContains(ipRange, address, true),
                testContains(ipRange, address.previous(), false),
                testContains(ipRange, address.next(), false),
                testContains(ipRange, null, false),
                testContains(ipRange, IPv6Address.LOCALHOST, false),
        };
    }

    private <IP extends IPAddress<IP>> DynamicTest testContains(IPRange<IP> ipRange, IP address, boolean expected) {
        return dynamicTest(String.valueOf(address), () -> {
            assertEquals(expected, ipRange.contains(address));
            assertEquals(expected, ipRange.contains((Object) address));
        });
    }

    private DynamicTest testContains(IPRange<?> ipRange, Object object, boolean expected) {
        return dynamicTest(String.valueOf(object), () -> assertEquals(expected, ipRange.contains(object)));
    }

    @Test
    public void testIterator() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new SingletonIPRange.IPv4(address);
        Iterator<IPv4Address> iterator = ipRange.iterator();
        assertTrue(iterator.hasNext());
        assertSame(address, iterator.next());
        assertFalse(iterator.hasNext());
        try {
            iterator.next();
            fail("expected NoSuchElementException");
        } catch (@SuppressWarnings("unused") NoSuchElementException e) {
            // expected
        }
    }

    @TestFactory
    public DynamicTest[] testToArray() {
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

    @TestFactory
    public DynamicTest[] testContainsAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        return new DynamicTest[] {
                testContainsAll(ipRange, Collections.emptyList(), true),
                testContainsAll(ipRange, ipRange, true),
                testContainsAll(ipRange, Collections.singleton(address), true),
                testContainsAll(ipRange, Arrays.asList(address, address), true),
                testContainsAll(ipRange, Arrays.asList(address, address.next()), false),
                testContainsAll(ipRange, Arrays.asList(address.previous(), address), false),
        };
    }

    private DynamicTest testContainsAll(IPRange<?> ipRange, Collection<?> c, boolean expected) {
        return dynamicTest(c.toString(), () -> assertEquals(expected, ipRange.containsAll(c)));
    }

    @TestFactory
    public DynamicTest[] testEquals() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        return new DynamicTest[] {
                testEquals(ipRange, null, false),
                testEquals(ipRange, "foo", false),
                testEquals(ipRange, address.to(IPv4Address.MAX_VALUE), false),
                testEquals(ipRange, ipRange, true),
                testEquals(ipRange, address.to(address), true),
                testEquals(ipRange, new IPRangeImpl.IPv4(address, address), true),
                testEquals(ipRange, address.previous().to(address), false),
                testEquals(ipRange, address.to(address.next()), false),
        };
    }

    private DynamicTest testEquals(IPRange<?> ipRange, Object object, boolean expected) {
        return dynamicTest(String.valueOf(object), () -> assertEquals(expected, ipRange.equals(object)));
    }

    @Test
    public void testHashCode() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals(ipRange.hashCode(), ipRange.hashCode());
        assertEquals(address.hashCode() ^ address.hashCode(), ipRange.hashCode());
    }

    @Test
    public void testToString() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        assertEquals("[127.0.0.1]", ipRange.toString());
        // test caching
        assertSame(ipRange.toString(), ipRange.toString());
    }

    @Test
    public void testForEach() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<?> ipRange = new SingletonIPRange.IPv4(address);
        @SuppressWarnings("unchecked")
        Consumer<Object> action = mock(Consumer.class);
        ipRange.forEach(action);
        verify(action).accept(address);
        verifyNoMoreInteractions(action);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testSpliterator() {
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
