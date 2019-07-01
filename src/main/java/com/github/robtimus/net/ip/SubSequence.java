/*
 * SubSequence.java
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

class SubSequence implements CharSequence {

    private final CharSequence s;
    private final int offset;
    private final int limit;

    SubSequence(CharSequence s, int offset, int limit) {
        this.s = s;
        this.offset = offset;
        this.limit = limit;
    }

    @Override
    public int length() {
        return limit - offset;
    }

    @Override
    public char charAt(int index) {
        return s.charAt(index + offset);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        throw new UnsupportedOperationException();
    }
}
