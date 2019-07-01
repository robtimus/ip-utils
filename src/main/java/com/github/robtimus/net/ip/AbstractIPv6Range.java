/*
 * AbstractIPv6Range.java
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

import java.util.Spliterator;

/**
 * A skeleton implementation of the {@link IPRange} interface for IPv6 addresses.
 *
 * @author Rob Spoor
 */
public abstract class AbstractIPv6Range extends AbstractIPRange<IPv6Address> implements IPv6Range {

    private int size = 0;

    /**
     * {@inheritDoc}
     * <p>
     * This implementation computes the size from {@link #from()} and {@link #to()}, caching its value for performance.
     */
    @Override
    public int size() {
        if (size == 0) {
            size = computeSize(from(), to());
        }
        return size;
    }

    static int computeSize(IPv6Address from, IPv6Address to) {
        if (from.highAddress == to.highAddress) {
            long difference = to.lowAddress - from.lowAddress;
            // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
            return (int) (difference < 0 || difference >= Integer.MAX_VALUE ? Integer.MAX_VALUE : difference + 1);
        }
        if (from.highAddress == to.highAddress - 1) {
            long fromDifference = IPv6Address.MAX_LOW_ADDRESS - from.lowAddress;
            if (fromDifference < 0 || fromDifference >= Integer.MAX_VALUE) {
                // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
                return Integer.MAX_VALUE;
            }
            long toDifference = to.lowAddress - IPv6Address.MIN_LOW_ADDRESS;
            if (toDifference < 0 || toDifference >= Integer.MAX_VALUE) {
                // if difference < 0 it overflowed, and the actual size > Long.MAX_VALUE
                return Integer.MAX_VALUE;
            }
            // plus 2: one for fromDifference and one for toDifference (both are inclusive)
            long difference = fromDifference + toDifference + 2;
            // 0 <= fromDifference < Integer.MAX_VALUE and 0 <= toDifference < Integer.MAX_VALUE, so 0 <= difference <= 2 * Integer.MAX_VALUE
            return (int) (difference >= Integer.MAX_VALUE ? Integer.MAX_VALUE : difference);
        }
        return Integer.MAX_VALUE;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation returns an {@link IPv6RangeSpliterator} for this range.
     */
    @Override
    public Spliterator<IPv6Address> spliterator() {
        return new IPv6RangeSpliterator(this);
    }
}
