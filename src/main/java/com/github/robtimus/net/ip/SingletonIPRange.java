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

abstract class SingletonIPRange<IP extends IPAddress<IP>> implements IPRange<IP> {

    private final IP ip;

    private String stringValue;

    SingletonIPRange(IP ip) {
        this.ip = ip;
    }

    // Query Operations

    @Override
    public IP from() {
        return ip;
    }

    @Override
    public IP to() {
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
    public boolean contains(IP ipAddress) {
        return ip.equals(ipAddress);
    }

    @Override
    public Iterator<IP> iterator() {
        return new Iterator<IP>() {
            private boolean done = false;

            @Override
            public boolean hasNext() {
                return !done;
            }

            @Override
            public IP next() {
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
    public void forEach(Consumer<? super IP> action) {
        action.accept(ip);
    }

    @Override
    public Spliterator<IP> spliterator() {
        return new SingletonSpliterator<>(ip);
    }

    private static final class SingletonSpliterator<IP extends IPAddress<IP>> implements Spliterator<IP> {

        private final IP ip;

        private boolean done = false;

        private SingletonSpliterator(IP ip) {
            this.ip = ip;
        }

        @Override
        public boolean tryAdvance(Consumer<? super IP> action) {
            if (done) {
                return false;
            }
            done = true;
            action.accept(ip);
            return true;
        }

        @Override
        public void forEachRemaining(Consumer<? super IP> action) {
            if (!done) {
                done = true;
                action.accept(ip);
            }
        }

        @Override
        public Spliterator<IP> trySplit() {
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
        public Comparator<? super IP> getComparator() {
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
