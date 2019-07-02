/*
 * IPRangeSpliterator.java
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

import java.util.Comparator;
import java.util.Spliterator;
import java.util.function.Consumer;

/**
 * A spliterator for IP ranges.
 *
 * @author Rob Spoor
 * @param <IP> The supported type of IP address.
 */
public abstract class IPRangeSpliterator<IP extends IPAddress<IP>> implements Spliterator<IP> {

    /**
     * A bit mask with the minimal characteristics that should be returned from {@link #characteristics()}:
     * {@link Spliterator#ORDERED}, {@link Spliterator#DISTINCT}, {@link Spliterator#SORTED}, {@link Spliterator#NONNULL} and
     * {@link Spliterator#IMMUTABLE}. Sub classes can additionally return {@link Spliterator#SIZED} and/or {@link Spliterator#SUBSIZED}.
     */
    protected static final int MINIMAL_CHARACTERISTICS = ORDERED | DISTINCT | SORTED | NONNULL | IMMUTABLE;

    final IP to;
    IP current;

    IPRangeSpliterator(IP from, IP to) {
        this.to = to;
        this.current = from;
    }

    @Override
    public boolean tryAdvance(Consumer<? super IP> action) {
        if (current != null && current.compareTo(to) <= 0) {
            action.accept(current);
            current = current.hasNext() ? current.next() : null;
            return true;
        }
        return false;
    }

    @Override
    public Comparator<? super IP> getComparator() {
        return null;
    }
}
