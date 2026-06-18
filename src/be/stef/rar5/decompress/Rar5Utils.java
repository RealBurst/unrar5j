/*
 * Copyright 2025 Stephane Bury
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
package be.stef.rar5.decompress;

/**
 * RAR5-specific decoding helpers that operate on a {@link Rar5BitDecoder}.
 *
 * <p>These were previously kept in the common {@code be.stef.rar.util.Utils}
 * class; they are RAR5-only and live here to keep the shared utilities free of
 * any dependency on the RAR5 bit decoder.</p>
 *
 * @author Stef
 * @since 1.0
 */
public final class Rar5Utils {

    private Rar5Utils() {
        // Utility class - no instantiation
    }

    /**
     * Reads a 32-bit unsigned integer from the bit stream.
     *
     * @param bi the bit decoder
     * @return the 32-bit value
     */
    public static int readUInt32(Rar5BitDecoder bi) {
        int numBits = (bi.readBits9Fix(2) * 8) + 8;
        int v = 0;
        int i = 0;
        do {
            v += bi.readBits9Fix(8) << i;
            i += 8;
        } while (i != numBits);
        return v;
    }

    /**
     * Copies bytes for match decoding.
     *
     * @param offset  not used (kept for API compatibility)
     * @param dest    destination array
     * @param destPos destination position
     * @param src     source array
     * @param srcPos  source position
     * @param lim     limit position
     */
    public static void copyMatch(int offset, byte[] dest, int destPos, byte[] src, int srcPos, int lim) {
        int len = lim - destPos;
        for (int i = 0; i < len; i++) {
            dest[destPos++] = src[srcPos++];
        }
    }

    /**
     * Converts a slot value to a length using the bit stream.
     *
     * @param bitStream the bit stream to read from
     * @param slot      the slot value
     * @return the decoded length
     */
    public static int slotToLen(Rar5BitDecoder bitStream, int slot) {
        int numBits = (slot >> 2) - 1;
        return ((4 | (slot & 3)) << numBits) + bitStream.readBits9(numBits);
    }
}
