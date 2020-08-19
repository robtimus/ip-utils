/*
 * IPRange.java
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
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Represents a range of consecutive IP addresses.
 * <p>
 * IP ranges are immutable collections of IP addresses. Any attempt to modify them will must result in an {@link UnsupportedOperationException}.
 * <p>
 * <b>Warning</b>: IP ranges can be very large; IPv4 ranges can contain up to 2<sup>32</sup> IP addresses, and IPv6 ranges can contain up to
 * 2<sup>128</sup> IP addresses. Iterating over such large IP ranges can take a long time, and calling {@link #toArray()} or
 * {@link #toArray(Object[])} can cause {@link OutOfMemoryError}s.
 *
 * @author Rob Spoor
 * @param <IP> The type of IP address in the range.
 */
public interface IPRange<IP extends IPAddress<IP>> extends Collection<IP> {

    // Query Operations

    /**
     * Returns the first IP address in this range.
     *
     * @return The first IP address in this range.
     */
    IP from();

    /**
     * Returns the last IP address in this range.
     * This is possibly the same IP address as {@link #from()} if the IP range contains only one IP address.
     *
     * @return The last IP address in this range.
     */
    IP to();

    /**
     * Returns the number of IP addresses in this IP range. This number must be at least 1.
     */
    @Override
    int size();

    /**
     * Returns whether or not this IP range is empty. This must always be {@code false}.
     */
    @Override
    default boolean isEmpty() {
        return false;
    }

    /**
     * Returns whether or not an object is contained in this IP range.
     * This method should return the result of {@link #contains(IPAddress)} for compatible objects, or {@code false} otherwise
     * (including {@code null}).
     * <p>
     * This implementation checks if the given element is an instance of the class of {@link #from()};
     * if so, it delegates to {@link #contains(IPAddress)}.
     */
    @Override
    @SuppressWarnings("unchecked")
    default boolean contains(Object o) {
        return from().getClass().isInstance(o) && contains((IP) o);
    }

    /**
     * Returns whether or not an IP address is in this IP range.
     * <p>
     * This implementation returns {@code true} only if the given IP address is not {@code null}, is not smaller than {@link #from()} and not larger
     * than {@link #to()}.
     *
     * @param ipAddress The IP address to check.
     * @return {@code true} if the given IP address is in this IP range, or {@code false} otherwise.
     * @see IPAddress#compareTo(Object)
     */
    default boolean contains(IP ipAddress) {
        return ipAddress != null && from().compareTo(ipAddress) <= 0 && ipAddress.compareTo(to()) <= 0;
    }

    /**
     * Returns an iterator over the IP addresses in this IP range. The IP addresses must be returned in order, from smallest to largest.
     * <p>
     * The returned iterator must throw an {@link UnsupportedOperationException} when its {@link Iterator#remove()} method is called.
     * <p>
     * This implementation returns an iterator that starts at {@link #from()} and iterates up to and including {@link #to()}.
     */
    @Override
    default Iterator<IP> iterator() {
        return new Iterator<IP>() {
            private IP current = from();

            @Override
            public boolean hasNext() {
                return current != null && current.compareTo(to()) <= 0;
            }

            @Override
            public IP next() {
                if (hasNext()) {
                    IP next = current;
                    current = current.hasNext() ? current.next() : null;
                    return next;
                }
                throw new NoSuchElementException();
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation return an array containing all IP addresses returned by iterating from {@link #from()} to {@link #to()} inclusive.
     */
    @Override
    default Object[] toArray() {
        Object[] result = new Object[size()];
        int i = 0;
        // exclude to here, because to.next() will not be allowed if to is the maximum IP address for its type
        for (IP ip = from(); ip.compareTo(to()) < 0; ip = ip.next()) {
            result[i++] = ip;
        }
        result[i] = to();
        return result;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation return an array containing all IP addresses returned by iterating from {@link #from()} to {@link #to()} inclusive.
     * If the given array is not large enough to contain all IP addresses a new array is created with a length equal to the number of IP addresses.
     */
    @Override
    @SuppressWarnings("unchecked")
    default <T> T[] toArray(T[] a) {
        int size = size();
        if (a.length < size) {
            a = (T[]) Array.newInstance(a.getClass().getComponentType(), size);
        }
        Object[] result = a;
        int i = 0;
        // exclude to here, because to.next() will not be allowed if to is the maximum IP address for its type
        for (IP ip = from(); ip.compareTo(to()) < 0; ip = ip.next()) {
            result[i++] = ip;
        }
        result[i] = to();

        if (a.length > size) {
            a[size] = null;
        }
        return a;
    }

    // Modification Operations

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean add(IP ipAddress) {
        throw new UnsupportedOperationException();
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean remove(Object o) {
        throw new UnsupportedOperationException();
    }

    // Bulk Operations

    /**
     * {@inheritDoc}
     * <p>
     * If the given collection collection is another IP range, this implementation checks if this {@link #contains(Object)} returns {@code true}
     * for both {@link #from() ipRange.from()} and {@link #to() ipRange.to()}, where {@code ipRange} is the given collection cast to {@code IPRange}.
     * Because IP ranges contain consecutive IP ranges, this IP range then automatically contains the entire IP range.
     * <p>
     * Otherwise, this implementation iterates over the given collection, checking for each element if it is contained in this IP range according to
     * {@link #contains(Object)}.
     */
    @Override
    default boolean containsAll(Collection<?> c) {
        if (c instanceof IPRange<?>) {
            IPRange<?> ipRange = (IPRange<?>) c;
            return contains(ipRange.from()) && contains(ipRange.to());
        }
        for (Object e : c) {
            if (!contains(e)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean addAll(Collection<? extends IP> c) {
        throw new UnsupportedOperationException();
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean removeAll(Collection<?> c) {
        throw new UnsupportedOperationException();
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean removeIf(Predicate<? super IP> filter) {
        throw new UnsupportedOperationException();
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default boolean retainAll(Collection<?> c) {
        throw new UnsupportedOperationException();
    }

    /**
     * Throws an {@link UnsupportedOperationException}.
     */
    @Override
    default void clear() {
        throw new UnsupportedOperationException();
    }

    // Comparison and hashing

    /**
     * Compares the specified object with this IP range for equality.
     * Returns {@code true} if and only if the specified object is also an IP range,
     * and both IP ranges have the same {@link #from() from} and {@link #to() to} addresses.
     * This implies that both IP ranges contain the same IP addresses.
     * <p>
     * More formally, two IP ranges {@code range1} and {@code range2} are equal if
     * <pre>{@code range1.from().equals(range2.from()) && range1.to().equals(range2.to())}</pre>
     */
    @Override
    boolean equals(Object o);

    /**
     * Returns the hash code value for this IP range.
     * The hash code of an IP range is defined to be the result of the following calculation:
     * <pre>{@code from().hashCode() ^ to().hashCode()}</pre>
     * This ensures that {@code range1.equals(range2)} implies that {@code range1.hashCode() == range2.hashCode()} for any two IP ranges
     * {@code range1} and {@code range2}, as required by the general contract of {@link Object#hashCode()}.
     */
    @Override
    int hashCode();

    // Stream / Iterable

    /**
     * {@inheritDoc}
     * <p>
     * This implementation iterates over all IP addresses from {@link #from()} to {@link #to()} inclusive, calling the given action for each one.
     */
    @Override
    default void forEach(Consumer<? super IP> action) {
        // exclude to here, because to.next() will not be allowed if to is the maximum IP address for its type
        for (IP ip = from(); ip.compareTo(to()) < 0; ip = ip.next()) {
            action.accept(ip);
        }
        action.accept(to());
    }
}
