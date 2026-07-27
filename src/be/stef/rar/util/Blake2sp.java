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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Pure Java implementation of BLAKE2sp (BLAKE2s parallel, 8 leaves).
 *
 * <p>BLAKE2sp hashes input with 8 independent BLAKE2s leaf instances, then
 * combines their digests with a single BLAKE2s root node. Output: 32 bytes.
 * This mirrors the reference C implementation (Neves, CC0/Apache-2.0):
 * data is consumed in 512-byte super-blocks (8 leaves × 64-byte blocks);
 * the trailing remainder is distributed to the leaves at finalisation.</p>
 *
 * <p>Data is processed in streaming fashion — memory use is bounded and
 * independent of input size, so multi-gigabyte files hash without buffering.</p>
 *
 * @author Stef
 * @since 2.0.1
 */
public final class Blake2sp {

    private static final int DEGREE      = 8;
    private static final int DIGEST_LEN  = 32;
    private static final int BLOCK_SIZE  = 64;
    private static final int SUPER_BLOCK = DEGREE * BLOCK_SIZE; // 512

    private static final int[] IV = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final byte[][] SIGMA = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
        {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
        {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
        { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
        { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
        { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
        {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
        {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
        { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    };

    // ── BLAKE2s single-instance state (leaf or root) ────────────────────────

    /**
     * A single BLAKE2s hashing state, faithfully mirroring the reference
     * implementation's update/final buffering semantics.
     */
    private static final class Blake2s {
        final int[]  h   = new int[8];
        final long[] t   = new long[2];   // 64-bit byte counter (t[0] low, t[1] high)
        final byte[] buf = new byte[BLOCK_SIZE];
        int     buflen   = 0;
        boolean lastNode = false;

        void incrementCounter(long inc) {
            t[0] += inc;
            if (t[0] < inc) t[1]++; // carry on unsigned overflow (rare)
        }

        /** Mirror of blake2s_update: note the strict {@code > BLOCK_SIZE} test. */
        void update(byte[] in, int off, int inlen) {
            if (inlen <= 0) return;
            int left = buflen;
            int fill = BLOCK_SIZE - left;
            if (inlen > fill) {
                buflen = 0;
                System.arraycopy(in, off, buf, left, fill);
                incrementCounter(BLOCK_SIZE);
                compress(this, buf, 0, false);
                off += fill; inlen -= fill;
                while (inlen > BLOCK_SIZE) {
                    incrementCounter(BLOCK_SIZE);
                    compress(this, in, off, false);
                    off += BLOCK_SIZE; inlen -= BLOCK_SIZE;
                }
            }
            System.arraycopy(in, off, buf, buflen, inlen);
            buflen += inlen;
        }

        /** Mirror of blake2s_final: pad the buffered remainder and compress as last block. */
        void finalize(byte[] out, int outOff) {
            incrementCounter(buflen);
            Arrays.fill(buf, buflen, BLOCK_SIZE, (byte) 0);
            compress(this, buf, 0, true);
            for (int i = 0; i < 8; i++) {
                int word = h[i];
                out[outOff + i * 4]     = (byte)  word;
                out[outOff + i * 4 + 1] = (byte) (word >>> 8);
                out[outOff + i * 4 + 2] = (byte) (word >>> 16);
                out[outOff + i * 4 + 3] = (byte) (word >>> 24);
            }
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────

    public static byte[] hash(File file) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(file), 65536)) {
            return hash(in);
        }
    }

    public static byte[] hash(InputStream in) throws IOException {
        Blake2s[] leaf = new Blake2s[DEGREE];
        for (int i = 0; i < DEGREE; i++) {
            leaf[i] = new Blake2s();
            initLeaf(leaf[i], i);
        }
        leaf[DEGREE - 1].lastNode = true; // mark last leaf

        // Consume the stream in 512-byte super-blocks. Within a full super-block,
        // leaf i receives bytes [i*64, (i+1)*64). Whatever remains at end-of-stream
        // (< 512 bytes) is handed to the leaves during finalisation, mirroring the
        // reference blake2sp_final distribution.
        byte[] sb = new byte[SUPER_BLOCK];
        int sbLen = 0;
        int n;
        // Accumulate into the super-block buffer; flush whenever it is full AND we
        // know more data follows (strictly, we flush a full 512 only when the NEXT
        // read returns data — but the leaf.update() strict-greater rule already keeps
        // the final block buffered per leaf, so flushing full super-blocks here is safe).
        while ((n = readSome(in, sb, sbLen, SUPER_BLOCK - sbLen)) > 0) {
            sbLen += n;
            if (sbLen == SUPER_BLOCK) {
                for (int i = 0; i < DEGREE; i++) {
                    leaf[i].update(sb, i * BLOCK_SIZE, BLOCK_SIZE);
                }
                sbLen = 0;
            }
        }

        // Distribute the trailing remainder (sbLen bytes, 0..511) across leaves,
        // exactly as blake2sp_final does: leaf i gets up to 64 bytes starting at i*64.
        for (int i = 0; i < DEGREE; i++) {
            int start = i * BLOCK_SIZE;
            if (sbLen > start) {
                int left = Math.min(sbLen - start, BLOCK_SIZE);
                leaf[i].update(sb, start, left);
            }
        }

        // Finalise leaves, then feed their digests to the root node.
        byte[] leafDigests = new byte[DEGREE * DIGEST_LEN];
        for (int i = 0; i < DEGREE; i++) {
            leaf[i].finalize(leafDigests, i * DIGEST_LEN);
        }

        Blake2s root = new Blake2s();
        initRoot(root);
        root.lastNode = true;
        root.update(leafDigests, 0, leafDigests.length);
        byte[] out = new byte[DIGEST_LEN];
        root.finalize(out, 0);
        return out;
    }

    public static boolean verify(File file, byte[] expectedHash) throws IOException {
        if (expectedHash == null || expectedHash.length != DIGEST_LEN) return false;
        return Arrays.equals(hash(file), expectedHash);
    }

    // ── Initialisation ─────────────────────────────────────────────────────

    private static void initLeaf(Blake2s s, int leafIndex) {
        int p0 = 0x02080020; // depth=2 | fanout=8 | key_len=0 | digest_len=32
        int p1 = 0;
        int p2 = leafIndex;   // node_offset low
        int p3 = 0x20000000;  // inner_length=32 | node_depth=0
        xorIV(s.h, new int[]{ p0, p1, p2, p3, 0, 0, 0, 0 });
    }

    private static void initRoot(Blake2s s) {
        int p0 = 0x02080020;
        int p1 = 0;
        int p2 = 0;
        int p3 = 0x20010000;  // inner_length=32 | node_depth=1
        xorIV(s.h, new int[]{ p0, p1, p2, p3, 0, 0, 0, 0 });
    }

    private static void xorIV(int[] h, int[] param) {
        for (int i = 0; i < 8; i++) h[i] = IV[i] ^ param[i];
    }

    // ── BLAKE2s compression ─────────────────────────────────────────────────

    private static void compress(Blake2s s, byte[] block, int off, boolean last) {
        int[] m = new int[16];
        for (int i = 0; i < 16; i++) {
            int base = off + i * 4;
            m[i] = (block[base]     & 0xFF)
                 | ((block[base+1] & 0xFF) <<  8)
                 | ((block[base+2] & 0xFF) << 16)
                 | ((block[base+3] & 0xFF) << 24);
        }

        int[] h = s.h;
        int v0=h[0], v1=h[1], v2=h[2],  v3=h[3];
        int v4=h[4], v5=h[5], v6=h[6],  v7=h[7];
        int v8=IV[0], v9=IV[1], v10=IV[2], v11=IV[3];
        int v12 = IV[4] ^ (int)  s.t[0];
        int v13 = IV[5] ^ (int)  s.t[1];
        int v14 = last          ? ~IV[6] : IV[6];
        int v15 = (last && s.lastNode) ? ~IV[7] : IV[7];

        for (int round = 0; round < 10; round++) {
            byte[] sg = SIGMA[round];
            int[] r;
            r=G(v0,v4,v8, v12,m[sg[0]], m[sg[1]]); v0=r[0];v4=r[1];v8=r[2]; v12=r[3];
            r=G(v1,v5,v9, v13,m[sg[2]], m[sg[3]]); v1=r[0];v5=r[1];v9=r[2]; v13=r[3];
            r=G(v2,v6,v10,v14,m[sg[4]], m[sg[5]]); v2=r[0];v6=r[1];v10=r[2];v14=r[3];
            r=G(v3,v7,v11,v15,m[sg[6]], m[sg[7]]); v3=r[0];v7=r[1];v11=r[2];v15=r[3];
            r=G(v0,v5,v10,v15,m[sg[8]], m[sg[9]]); v0=r[0];v5=r[1];v10=r[2];v15=r[3];
            r=G(v1,v6,v11,v12,m[sg[10]],m[sg[11]]);v1=r[0];v6=r[1];v11=r[2];v12=r[3];
            r=G(v2,v7,v8, v13,m[sg[12]],m[sg[13]]);v2=r[0];v7=r[1];v8=r[2]; v13=r[3];
            r=G(v3,v4,v9, v14,m[sg[14]],m[sg[15]]);v3=r[0];v4=r[1];v9=r[2]; v14=r[3];
        }

        h[0]^=v0^v8;  h[1]^=v1^v9;  h[2]^=v2^v10; h[3]^=v3^v11;
        h[4]^=v4^v12; h[5]^=v5^v13; h[6]^=v6^v14; h[7]^=v7^v15;
    }

    private static int[] G(int a, int b, int c, int d, int x, int y) {
        a += b + x; d = Integer.rotateRight(d ^ a, 16);
        c += d;     b = Integer.rotateRight(b ^ c, 12);
        a += b + y; d = Integer.rotateRight(d ^ a,  8);
        c += d;     b = Integer.rotateRight(b ^ c,  7);
        return new int[]{ a, b, c, d };
    }

    // ── Utility ────────────────────────────────────────────────────────────

    /** Reads up to {@code len} bytes; returns count read, or -1/0 at end of stream. */
    private static int readSome(InputStream in, byte[] buf, int off, int len) throws IOException {
        if (len == 0) return 0;
        return in.read(buf, off, len);
    }

    private Blake2sp() {}
}