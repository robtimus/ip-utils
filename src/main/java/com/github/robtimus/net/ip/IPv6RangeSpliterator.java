/*
 * IPv6RangeSpliterator.java
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
 * A spliterator for IPv6 ranges.
 *
 * @author Rob Spoor
 */
public final class IPv6RangeSpliterator extends IPRangeSpliterator<IPv6Address> {

    private final int characteristics;

    /**
     * Creates a new spliterator.
     *
     * @param range The IPv6 range to create a spliterator for.
     * @throws NullPointerException If the given IP range is {@code null}.
     */
    public IPv6RangeSpliterator(IPRange<IPv6Address> range) {
        super(range.from(), range.to());
        characteristics = MINIMAL_CHARACTERISTICS + (estimateSize() == Long.MAX_VALUE ? 0 : SIZED | SUBSIZED);
    }

    IPv6RangeSpliterator(IPv6Address from, IPv6Address to, int characteristics) {
        super(from, to);
        this.characteristics = characteristics;
    }

    @Override
    public IPv6RangeSpliterator trySplit() {
        if (current == null) {
            return null;
        }
        IPv6Address mid = current.mid(to);
        if (current.compareTo(mid) >= 0) {
            return null;
        }
        IPv6RangeSpliterator spliterator = new IPv6RangeSpliterator(current, mid.previous(), characteristics);
        current = mid;
        return spliterator;
    }

    @Override
    public int characteristics() {
        return characteristics;
    }

    @Override
    public long estimateSize() {
        if (current == null || current.compareTo(to) > 0) {
            return 0;
        }
        if (current.highAddress == to.highAddress) {
            long difference = to.lowAddress - current.lowAddress;
            // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
            return difference < 0 || difference == Long.MAX_VALUE ? Long.MAX_VALUE : difference + 1;
        }
        if (current.highAddress == to.highAddress - 1) {
            long fromDifference = IPv6Address.MAX_LOW_ADDRESS - current.lowAddress;
            if (fromDifference < 0) {
                // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
                return Long.MAX_VALUE;
            }
            long toDifference = to.lowAddress - IPv6Address.MIN_LOW_ADDRESS;
            if (toDifference < 0) {
                // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
                return Long.MAX_VALUE;
            }
            // plus 2: one for fromDifference and one for toDifference (both are inclusive)
            long difference = fromDifference + toDifference + 2;
            // if difference < 2 it overflowed, and the actual size > Long.MAX_VALUE
            return difference < 2 ? Long.MAX_VALUE : difference;
        }
        return Long.MAX_VALUE;
    }
}
