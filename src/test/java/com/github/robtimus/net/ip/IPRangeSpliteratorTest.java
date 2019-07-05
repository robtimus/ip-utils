/*
 * IPRangeSpliteratorTest.java
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

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import java.util.Spliterator;
import java.util.function.Consumer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

@SuppressWarnings({ "javadoc", "nls" })
public class IPRangeSpliteratorTest {

    @TestFactory
    @DisplayName("tryAdvance")
    @SuppressWarnings("unchecked")
    public DynamicTest[] testTryAdvance() {
        return new DynamicTest[] {
                dynamicTest("end before MAX_VALUE", () -> {
                    IPRangeSpliterator<?> spliterator = new TestSpliterator(IPv4Address.LOCALHOST.previous(), IPv4Address.LOCALHOST.next());
                    Consumer<? super IPAddress<?>> action = mock(Consumer.class);
                    while (spliterator.tryAdvance(action)) {
                        // do nothing
                    }
                    verify(action).accept(IPv4Address.LOCALHOST.previous());
                    verify(action).accept(IPv4Address.LOCALHOST);
                    verify(action).accept(IPv4Address.LOCALHOST.next());
                    verifyNoMoreInteractions(action);
                }),
                dynamicTest("end is MAX_VALUE", () -> {
                    IPRangeSpliterator<?> spliterator = new TestSpliterator(IPv4Address.MAX_VALUE.previous().previous(), IPv4Address.MAX_VALUE);
                    Consumer<? super IPAddress<?>> action = mock(Consumer.class);
                    while (spliterator.tryAdvance(action)) {
                        // do nothing
                    }
                    verify(action).accept(IPv4Address.MAX_VALUE.previous().previous());
                    verify(action).accept(IPv4Address.MAX_VALUE.previous());
                    verify(action).accept(IPv4Address.MAX_VALUE);
                    verifyNoMoreInteractions(action);
                }),
        };
    }

    @Test
    @DisplayName("getComparator")
    public void testGetComparator() {
        IPRangeSpliterator<?> spliterator = new TestSpliterator(IPv4Address.MIN_VALUE, IPv4Address.MAX_VALUE);
        assertNull(spliterator.getComparator());
    }

    private static final class TestSpliterator extends IPRangeSpliterator<IPv4Address> {

        private TestSpliterator(IPv4Address from, IPv4Address to) {
            super(from, to);
        }

        @Override
        public Spliterator<IPv4Address> trySplit() {
            throw new UnsupportedOperationException();
        }

        @Override
        public long estimateSize() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int characteristics() {
            throw new UnsupportedOperationException();
        }
    }
}
