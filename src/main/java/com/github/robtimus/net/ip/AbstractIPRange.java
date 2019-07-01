/*
 * AbstractIPRange.java
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
 * A skeleton implementation of the {@link IPRange} interface.
 *
 * @author Rob Spoor
 * @param <IP> The type of IP address in the range.
 */
public abstract class AbstractIPRange<IP extends IPAddress<IP>> implements IPRange<IP> {

    // Comparison and hashing

    /**
     * {@inheritDoc}
     * <p>
     * This implementation first checks if the given object is this IP range; if so it returns true.
     * If not, it checks if the given object is another IP range. If so, it returns {@code from().equals(range.from()) && to().equals(range.to())}
     * according to the contract of {@link IPRange#equals(Object)}.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof IPRange<?>) {
            IPRange<?> range = (IPRange<?>) obj;
            return from().equals(range.from()) && to().equals(range.to());
        }
        return false;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation returns {@code from().hashCode() ^ to().hashCode()} according to the contract of {@link IPRange#hashCode()}.
     */
    @Override
    public int hashCode() {
        return from().hashCode() ^ to().hashCode();
    }
}
