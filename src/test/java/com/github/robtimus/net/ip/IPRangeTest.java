/*
 * IPRangeTest.java
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Consumer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class IPRangeTest {

    @Test
    public void testIsEmpty() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertFalse(ipRange.isEmpty());
    }

    @TestFactory
    public DynamicTest[] testContains() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        return new DynamicTest[] {
                testContains(ipRange, address, true),
                testContains(ipRange, address.previous(), true),
                testContains(ipRange, address.next(), true),
                testContains(ipRange, address.previous().previous(), false),
                testContains(ipRange, address.next().next(), false),
                testContains(ipRange, (IPv4Address) null, false),
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

    @TestFactory
    public DynamicTest[] testIterator() {
        return new DynamicTest[] {
                dynamicTest("end before MAX_VALUE", () -> {
                    IPv4Address address = IPv4Address.LOCALHOST;
                    IPRange<IPv4Address> ipRange = new TestRange(address);
                    Iterator<IPv4Address> iterator = ipRange.iterator();
                    assertTrue(iterator.hasNext());
                    assertEquals(address.previous(), iterator.next());
                    assertTrue(iterator.hasNext());
                    assertEquals(address, iterator.next());
                    assertTrue(iterator.hasNext());
                    assertEquals(address.next(), iterator.next());
                    assertFalse(iterator.hasNext());
                    assertThrows(NoSuchElementException.class, iterator::next);
                }),
                dynamicTest("end is MAX_VALUE", () -> {
                    IPRange<IPv4Address> ipRange = new IPRange<IPv4Address>() {
                        @Override
                        public IPv4Address from() {
                            return IPv4Address.MAX_VALUE.previous().previous();
                        }

                        @Override
                        public IPv4Address to() {
                            return IPv4Address.MAX_VALUE;
                        }

                        @Override
                        public int size() {
                            return 3;
                        }
                    };
                    Iterator<IPv4Address> iterator = ipRange.iterator();
                    assertTrue(iterator.hasNext());
                    assertEquals(IPv4Address.MAX_VALUE.previous().previous(), iterator.next());
                    assertTrue(iterator.hasNext());
                    assertEquals(IPv4Address.MAX_VALUE.previous(), iterator.next());
                    assertTrue(iterator.hasNext());
                    assertEquals(IPv4Address.MAX_VALUE, iterator.next());
                    assertFalse(iterator.hasNext());
                    assertThrows(NoSuchElementException.class, iterator::next);
                }),
        };
    }

    @TestFactory
    public DynamicTest[] testToArray() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        return new DynamicTest[] {
                dynamicTest("no array", () -> {
                    Object[] array = ipRange.toArray();
                    assertEquals(Object[].class, array.getClass());
                    assertArrayEquals(new Object[] { address.previous(), address, address.next() }, array);
                }),
                dynamicTest("empty array", () -> {
                    Object[] a = new IPv4Address[0];
                    Object[] array = ipRange.toArray(a);
                    assertNotSame(a, array);
                    assertEquals(IPv4Address[].class, array.getClass());
                    assertArrayEquals(new IPv4Address[] { address.previous(), address, address.next() }, array);
                }),
                dynamicTest("array of same size", () -> {
                    Object[] a = new IPv4Address[3];
                    Object[] array = ipRange.toArray(a);
                    assertSame(a, array);
                    assertArrayEquals(new IPv4Address[] { address.previous(), address, address.next() }, array);
                }),
                dynamicTest("array of larger size", () -> {
                    Object[] a = new IPv4Address[] { null, null, null, IPv4Address.MAX_VALUE };
                    Object[] array = ipRange.toArray(a);
                    assertSame(a, array);
                    assertArrayEquals(new IPv4Address[] { address.previous(), address, address.next(), null }, array);
                }),
        };
    }

    @Test
    public void testAdd() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.add(address));
    }

    @Test
    public void testRemove() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.remove(address));
    }

    @TestFactory
    public DynamicTest[] testContainsAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        return new DynamicTest[] {
                testContainsAll(ipRange, Collections.emptyList(), true),
                testContainsAll(ipRange, ipRange, true),
                testContainsAll(ipRange, Collections.singleton(address), true),
                testContainsAll(ipRange, Arrays.asList(address, address), true),
                testContainsAll(ipRange, Arrays.asList(address, address.next()), true),
                testContainsAll(ipRange, Arrays.asList(address.previous(), address), true),
                testContainsAll(ipRange, Arrays.asList(address, address.next().next()), false),
                testContainsAll(ipRange, Arrays.asList(address.previous().previous(), address), false),
                testContainsAll(ipRange, address.asRange(), true),
                testContainsAll(ipRange, IPv4Address.MIN_VALUE.to(address), false),
                testContainsAll(ipRange, address.to(IPv4Address.MAX_VALUE), false),
        };
    }

    private <IP extends IPAddress<IP>> DynamicTest testContainsAll(IPRange<IP> ipRange, Collection<?> c, boolean expected) {
        return dynamicTest(c.toString(), () -> assertEquals(expected, ipRange.containsAll(c)));
    }

    @Test
    public void testAddAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.addAll(Collections.emptyList()));
    }

    @Test
    public void testRemoveAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.removeAll(Collections.emptyList()));
    }

    @Test
    public void testRemoveIf() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.removeIf(t -> false));
    }

    @Test
    public void testRetainAll() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.retainAll(Collections.emptyList()));
    }

    @Test
    public void testClear() {
        IPv4Address address = IPv4Address.LOCALHOST;
        IPRange<IPv4Address> ipRange = new TestRange(address);
        assertThrows(UnsupportedOperationException.class, () -> ipRange.clear());
    }

    @TestFactory
    public DynamicTest[] testForEach() {
        return new DynamicTest[] {
                dynamicTest("end before MAX_VALUE", () -> {
                    IPv4Address address = IPv4Address.LOCALHOST;
                    IPRange<IPv4Address> ipRange = new TestRange(address);
                    @SuppressWarnings("unchecked")
                    Consumer<Object> action = mock(Consumer.class);
                    ipRange.forEach(action);
                    verify(action).accept(address.previous());
                    verify(action).accept(address);
                    verify(action).accept(address.next());
                    verifyNoMoreInteractions(action);
                }),
                dynamicTest("end is MAX_VALUE", () -> {
                    IPRange<IPv4Address> ipRange = new IPRange<IPv4Address>() {
                        @Override
                        public IPv4Address from() {
                            return IPv4Address.MAX_VALUE.previous().previous();
                        }

                        @Override
                        public IPv4Address to() {
                            return IPv4Address.MAX_VALUE;
                        }

                        @Override
                        public int size() {
                            return 3;
                        }
                    };
                    @SuppressWarnings("unchecked")
                    Consumer<Object> action = mock(Consumer.class);
                    ipRange.forEach(action);
                    verify(action).accept(IPv4Address.MAX_VALUE.previous().previous());
                    verify(action).accept(IPv4Address.MAX_VALUE.previous());
                    verify(action).accept(IPv4Address.MAX_VALUE);
                    verifyNoMoreInteractions(action);
                }),
        };
    }

    private static final class TestRange implements IPRange<IPv4Address> {

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
