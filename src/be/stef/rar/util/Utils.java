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
package be.stef.rar.util;

import java.util.Arrays;

/**
 * Common byte and array utility methods shared across RAR4 and RAR5
 * processing.
 * 
 * <p>Pure helpers (no dependency on any format-specific type): little-endian
 * reads/writes, hex formatting, array copies and zeroing.</p>
 * 
 * @author Stef
 * @since 1.0
 */
public final class Utils {
    
    private Utils() {
        // Utility class - no instantiation
    }
    
    /**
     * Converts a byte array to a hexadecimal string representation.
     * 
     * @param bytes the byte array to convert
     * @return hexadecimal string with uppercase letters and space separators,
     *         or "null" if input is null
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }
    
    /**
     * Converts a byte array to a compact hexadecimal string (no spaces).
     * 
     * @param bytes the byte array to convert
     * @return hexadecimal string with lowercase letters,
     *         or "null" if input is null
     */
    public static String bytesToHexCompact(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    
    /**
     * Reads a 32-bit unsigned integer in little-endian byte order.
     * 
     * @param data the byte array to read from
     * @param offset the starting offset
     * @return the unsigned 32-bit value as a long
     * @throws ArrayIndexOutOfBoundsException if offset + 4 exceeds array length
     */
    public static long readUInt32LE(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF)) |
               ((long) (data[offset + 1] & 0xFF) << 8) |
               ((long) (data[offset + 2] & 0xFF) << 16) |
               ((long) (data[offset + 3] & 0xFF) << 24);
    }
    
    /**
     * Reads a 64-bit unsigned integer in little-endian byte order.
     * 
     * @param data the byte array to read from
     * @param offset the starting offset
     * @return the 64-bit value as a long
     * @throws ArrayIndexOutOfBoundsException if offset + 8 exceeds array length
     */
    public static long readUInt64LE(byte[] data, int offset) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((long) (data[offset + i] & 0xFF)) << (i * 8);
        }
        return result;
    }
    
    /**
     * Reads a 16-bit unsigned integer in little-endian byte order.
     * 
     * @param data the byte array to read from
     * @param offset the starting offset
     * @return the unsigned 16-bit value as an int
     * @throws ArrayIndexOutOfBoundsException if offset + 2 exceeds array length
     */
    public static int readUInt16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
               ((data[offset + 1] & 0xFF) << 8);
    }
    
    /**
     * Writes a 32-bit integer in little-endian byte order.
     * 
     * @param data the byte array to write to
     * @param offset the starting offset
     * @param value the value to write
     * @throws ArrayIndexOutOfBoundsException if offset + 4 exceeds array length
     */
    public static void writeUInt32LE(byte[] data, int offset, int value) {
        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >> 8);
        data[offset + 2] = (byte) (value >> 16);
        data[offset + 3] = (byte) (value >> 24);
    }
    
    /**
     * Aligns a size value to a 16-byte boundary (AES block size).
     * 
     * @param size the size to align
     * @return the aligned size
     */
    public static long alignToAesBlock(long size) {
        return ((size + 15) / 16) * 16;
    }
    
    /**
     * Copies a portion of a byte array.
     * 
     * @param source the source array
     * @param offset the starting offset in the source
     * @param length the number of bytes to copy
     * @return a new byte array containing the copied bytes
     * @throws ArrayIndexOutOfBoundsException if the range exceeds source bounds
     */
    public static byte[] copyBytes(byte[] source, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, offset, result, 0, length);
        return result;
    }
    
    /**
     * Fills a portion of an array with zeros.
     * 
     * @param array the array to fill
     * @param offset starting offset
     * @param length number of bytes to zero
     */
    public static void zeroMemory(byte[] array, int offset, int length) {
        Arrays.fill(array, offset, offset + length, (byte) 0);
    }
    
    /**
     * Fills an entire array with zeros.
     * 
     * @param array the array to fill
     */
    public static void zeroMemory(byte[] array) {
        Arrays.fill(array, (byte) 0);
    }
    
}
