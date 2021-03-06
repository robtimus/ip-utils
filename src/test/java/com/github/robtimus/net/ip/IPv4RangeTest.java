/*
 * IPv4RangeTest.java
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

import static org.junit.jupiter.api.Assertions.assertSame;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class IPv4RangeTest {

    @Test
    @DisplayName("all()")
    void testAll() {
        IPv4Range ipRange = IPv4Range.all();
        assertSame(IPv4Address.MIN_VALUE, ipRange.from());
        assertSame(IPv4Address.MAX_VALUE, ipRange.to());
        assertSame(ipRange, IPv4Range.all());
    }
}
