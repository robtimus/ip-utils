/*
 * IPv4RangeSpliterator.java
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

/**
 * A spliterator for IPv4 ranges.
 *
 * @author Rob Spoor
 */
public final class IPv4RangeSpliterator extends IPRangeSpliterator<IPv4Address> {

    /**
     * Creates a new spliterator.
     *
     * @param range The IPv4 range to create a spliterator for.
     * @throws NullPointerException If the given IP range is {@code null}.
     */
    public IPv4RangeSpliterator(IPRange<IPv4Address> range) {
        this(range.from(), range.to());
    }

    IPv4RangeSpliterator(IPv4Address from, IPv4Address to) {
        super(from, to);
    }

    @Override
    public IPv4RangeSpliterator trySplit() {
        if (current == null) {
            return null;
        }
        IPv4Address mid = current.mid(to);
        if (current.compareTo(mid) >= 0) {
            return null;
        }
        IPv4RangeSpliterator spliterator = new IPv4RangeSpliterator(current, mid.previous());
        current = mid;
        return spliterator;
    }

    @Override
    public long estimateSize() {
        if (current == null || current.compareTo(to) > 0) {
            return 0;
        }
        long fromAddress = current.address & 0xFFFF_FFFFL;
        long toAddress = to.address & 0xFFFF_FFFFL;
        // both fromAddress and toAddress are between 0 and 0xFFFF_FFFFL inclusive
        return toAddress - fromAddress + 1L;
    }

    @Override
    public int characteristics() {
        return MINIMAL_CHARACTERISTICS | SIZED | SUBSIZED;
    }
}
