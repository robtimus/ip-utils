/*
 * IPv4Range.java
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
 * Represents a range of consecutive IPv4 addresses.
 *
 * @author Rob Spoor
 */
public interface IPv4Range extends IPRange<IPv4Address> {

    /**
     * Returns an IP range that includes all possible IPv4 address.
     *
     * @return An IP range that includes all possible IPv4 address.
     */
    static IPv4Range all() {
        return IPRangeImpl.IPv4.ALL;
    }
}
