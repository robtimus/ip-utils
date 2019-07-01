/*
 * AbstractIPv4Range.java
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
 * A skeleton implementation of the {@link IPRange} interface for IPv4 addresses.
 *
 * @author Rob Spoor
 */
public abstract class AbstractIPv4Range extends AbstractIPRange<IPv4Address> implements IPv4Range {

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

    static int computeSize(IPv4Address from, IPv4Address to) {
        long fromAddress = from.address & 0xFFFF_FFFFL;
        long toAddress = to.address & 0xFFFF_FFFFL;
        // both fromAddress and toAddress are between 0 and 0xFFFF_FFFFL inclusive
        return (int) Math.min(toAddress - fromAddress + 1L, Integer.MAX_VALUE);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation returns an {@link IPv4RangeSpliterator} for this range.
     */
    @Override
    public Spliterator<IPv4Address> spliterator() {
        return new IPv4RangeSpliterator(this);
    }
}
