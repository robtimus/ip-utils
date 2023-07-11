/*
 * SingletonIPRange.java
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

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.function.Consumer;

abstract class SingletonIPRange<I extends IPAddress<I>> implements IPRange<I> {

    private final I ip;

    private String stringValue;

    SingletonIPRange(I ip) {
        this.ip = ip;
    }

    // Query Operations

    @Override
    public I from() {
        return ip;
    }

    @Override
    public I to() {
        return ip;
    }

    @Override
    public int size() {
        return 1;
    }

    @Override
    public boolean contains(Object o) {
        return ip.equals(o);
    }

    @Override
    public boolean contains(I ipAddress) {
        return ip.equals(ipAddress);
    }

    @Override
    public Iterator<I> iterator() {
        return new Iterator<I>() {
            private boolean done = false;

            @Override
            public boolean hasNext() {
                return !done;
            }

            @Override
            public I next() {
                if (done) {
                    throw new NoSuchElementException();
                }
                done = true;
                return ip;
            }
        };
    }

    @Override
    public Object[] toArray() {
        return new Object[] { ip };
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T[] toArray(T[] a) {
        if (a.length == 0) {
            a = (T[]) Array.newInstance(a.getClass().getComponentType(), 1);
        }
        Object[] result = a;
        result[0] = ip;

        if (a.length > 1) {
            a[1] = null;
        }
        return a;
    }

    // Bulk Operations

    @Override
    public boolean containsAll(Collection<?> c) {
        for (Object e : c) {
            if (!ip.equals(e)) {
                return false;
            }
        }
        return true;
    }

    // Comparison and hashing

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof IPRange<?>) {
            IPRange<?> range = (IPRange<?>) obj;
            return ip.equals(range.from()) && ip.equals(range.to());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return ip.hashCode() * 31 + ip.hashCode();
    }

    @Override
    @SuppressWarnings("nls")
    public String toString() {
        if (stringValue == null) {
            stringValue = "[" + ip + "]";
        }
        return stringValue;
    }

    // Stream / Iterable

    @Override
    public void forEach(Consumer<? super I> action) {
        action.accept(ip);
    }

    @Override
    public Spliterator<I> spliterator() {
        return new SingletonSpliterator<>(ip);
    }

    private static final class SingletonSpliterator<I extends IPAddress<I>> implements Spliterator<I> {

        private final I ip;

        private boolean done = false;

        private SingletonSpliterator(I ip) {
            this.ip = ip;
        }

        @Override
        public boolean tryAdvance(Consumer<? super I> action) {
            if (done) {
                return false;
            }
            done = true;
            action.accept(ip);
            return true;
        }

        @Override
        public void forEachRemaining(Consumer<? super I> action) {
            if (!done) {
                done = true;
                action.accept(ip);
            }
        }

        @Override
        public Spliterator<I> trySplit() {
            return null;
        }

        @Override
        public long estimateSize() {
            return done ? 0 : 1;
        }

        @Override
        public long getExactSizeIfKnown() {
            return estimateSize();
        }

        @Override
        public int characteristics() {
            return ORDERED | DISTINCT | SORTED | SIZED | NONNULL | IMMUTABLE | SUBSIZED;
        }

        @Override
        public Comparator<? super I> getComparator() {
            return null;
        }
    }

    static final class IPv4 extends SingletonIPRange<IPv4Address> implements IPv4Range {

        IPv4(IPv4Address ip) {
            super(ip);
        }
    }

    static final class IPv6 extends SingletonIPRange<IPv6Address> implements IPv6Range {

        IPv6(IPv6Address ip) {
            super(ip);
        }
    }
}
