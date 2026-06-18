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
package be.stef.rar5;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;
import be.stef.rar.ExtractionError;
import be.stef.rar.ExtractionResult;
import be.stef.rar.exceptions.RarCorruptedDataException;
import be.stef.rar.exceptions.RarDecryptException;
import be.stef.rar.util.NullOutputStream;
import be.stef.rar.util.BoundedInputStream;
import be.stef.rar.util.ProgressOutputStream;
import be.stef.rar.util.SafePathBuilder;
import be.stef.rar.util.VInt;
import be.stef.rar.util.VIntReader;
import be.stef.rar5.blocks.Rar5FileBlock;
import be.stef.rar5.blocks.Rar5MainArchiveBlock;
import be.stef.rar5.crypto.Rar5Crypto;
import be.stef.rar5.decompress.Rar5LZDecoder;
import be.stef.rar5.decompress.Rar5PropertyEncoder;
import be.stef.rar5.extra.Rar5ExtraCrypto;


/**
 * High-level API for extracting RAR5 archives.
 * 
 * <p>This class provides a simple interface for extracting files from RAR5 archives,
 * handling both encrypted and non-encrypted archives transparently.</p>
 * 
 * <h3>Basic Usage:</h3>
 * <pre>
 * // Extract without password
 * ExtractionResult result = Rar5Extractor.extract("archive.rar", "output/", null);
 * 
 * // Extract with password
 * ExtractionResult result = Rar5Extractor.extract("encrypted.rar", "output/", "password");
 * 
 * // Check results
 * System.out.println("Success: " + result.successCount + "/" + result.totalFiles);
 * </pre>
 * 
 * <h3>Check if Password Required:</h3>
 * <pre>
 * if (Rar5Extractor.isEncrypted("archive.rar")) {
 *     System.out.println("Password required");
 * }
 * </pre>
 * 
 * @author Stef
 * @since 1.0
 */
public class Rar5Extractor {
    private static Rar5LZDecoder sharedDecoder = null;
    public static boolean showProgress = true;    
    public static boolean isEncryptedArchive;
    public static SafePathBuilder pathBuilder;
    public static long maxCompressionRatio = 1000; //Maximum allowed compression ratio (unpackedSize / compressedSize). Default 1000:1
    
    /**
     * Checks if an archive requires a password (has encrypted headers).
     * 
     * @param archivePath path to the archive
     * @return true if password is required
     * @throws IOException if file cannot be read
     */
    public static boolean isEncrypted(String archivePath) throws IOException {
        byte[] header = readFileHeader(archivePath, 500);
        if (header == null || header.length < Rar5Constants.RAR5_SIGNATURE.length + 10) {
            return false;
        }
        
        // Verify RAR5 signature
        for (int i = 0; i < Rar5Constants.RAR5_SIGNATURE.length; i++) {
            if (header[i] != Rar5Constants.RAR5_SIGNATURE[i]) {
                return false;
            }
        }
        
        // Check first block type
        try {
            int offset = Rar5Constants.RAR5_SIGNATURE.length + 4;
            VInt headerSize = VIntReader.read(header, offset, header.length);
            if (headerSize == null) {
                return false;
            }
            offset += headerSize.length;
            
            VInt blockType = VIntReader.read(header, offset, header.length);
            return blockType != null && blockType.value == Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Extracts a RAR5 archive to the specified directory.
     * 
     * <p>Extraction process:</p>
     * <ol>
     *   <li>If headers are encrypted, decrypt them first</li>
     *   <li>Read archive structure</li>
     *   <li>For each file: decrypt (if needed), decompress, write to disk</li>
     *   <li>Verify CRC32 checksums</li>
     * </ol>
     * 
     * @param archivePath path to the archive file
     * @param outputDir directory to extract files to
     * @param password password for encrypted archives, or null
     * @return extraction result with success/error counts
     */
    
    public static ExtractionResult extract(String archivePath, String outputDir, String password) {
       return extract(archivePath, outputDir, password, null);
    }
    
    public static synchronized ExtractionResult extract(String archivePath, String outputDir, String password, String fileFilter) {
        ExtractionResult result = new ExtractionResult();
        File tempFile = null;
        isEncryptedArchive = false;
        
        result.archiveName = archivePath;
              
        try {
            File archiveFile = new File(archivePath);
            if (!archiveFile.exists()) {
               System.out.println("Archive ["+archiveFile.getCanonicalPath()+"] not found !");
                return result;
            }
            
            File outDir = new File(outputDir);
            if (!outDir.exists()) {
                outDir.mkdirs();
            }
            
            // Initialize SafePathBuilder for path traversal protection
            pathBuilder = new SafePathBuilder(outDir);
            
            // Step 1: Decrypt headers if needed
            if (isEncrypted(archivePath)) {
               isEncryptedArchive = true;
                if (password == null || password.isEmpty()) {
                    return result;
                }
                
                // Verify password BEFORE creating temp file
                Rar5ExtraCrypto archiveCrypto = readArchiveEncryptionInfo(archivePath);
                if (archiveCrypto != null && archiveCrypto.hasPasswordCheck()) {
                    try {
                        boolean passwordOk = Rar5Crypto.verifyPassword(password, archiveCrypto);
                        result.passwordStatus = passwordOk ? 1 : 2;
                        if (!passwordOk) {
                            System.out.println("ERROR: Wrong password for encrypted archive!");
                            return result;
                        }
                    } catch (Exception e) {
                        // Password verification failed, continue anyway
                    }
                }
                
                tempFile = File.createTempFile("unrar5j_dec_", ".rar");
                tempFile.deleteOnExit();
                Rar5HeaderDecryptor decryptor = new Rar5HeaderDecryptor(password);
                decryptor.decryptToFile(archivePath, tempFile.getAbsolutePath());

                archiveFile = tempFile;
            }
         
            // Step 2: Read archive headers (small, stays in memory)
            Rar5Reader reader = new Rar5Reader(password);
            if (!reader.read(archiveFile)) {
                return result;
            }

            // Multi-volume archive: delegate to the dedicated path.
            // (Kept fully separate from the single-volume flow below.)
            Rar5MainArchiveBlock mainArchive = reader.getMainArchive();
            if (mainArchive != null && mainArchive.isVolume()) {
                // Use the ORIGINAL archive path for volume discovery: when the
                // headers were decrypted to a temp file, archiveFile points at
                // that temp file, which has no sibling volumes on disk.
                return extractMultiVolume(new File(archivePath), outputDir, password,
                                          fileFilter, result, isEncryptedArchive);
            }

            List<Rar5FileBlock> fileBlocks = reader.getFileBlocks();
            result.totalFiles = fileBlocks.size();

            // Step 3: Extract each file using RandomAccessFile
            try (RandomAccessFile raf = new RandomAccessFile(archiveFile, "r")) {
                for (Rar5FileBlock file : fileBlocks) {
                    try {
                        boolean isTarget = (fileFilter == null || fileFilter.equals(file.getFileName()));
                       
                        if (file.isSolid() && !isTarget) {
                           // Solid archive: must decode but not write to disk
                           // The decoder must still run to keep its state consistent
                           extractFile(file, raf, reader, outputDir, password, result, false);
                           continue;
                        }
                       
                        if (!isTarget) {
                           continue;  // Non-solid: we can simply skip
                        }                        
                        extractFile(file, raf, reader, outputDir, password, result);
                        result.unpackedFiles.add(file.getFileName());
                    } catch (Exception e) {
                        result.errors.add(buildError(file, "Exception during extraction", e));
                        result.errorCount++;
                        result.failedFiles.add(file.getFileName());
                    }
                }
            }            
            
        } catch (Exception e) {
            // Fatal error
            System.err.println("Fatal extraction error: " + e.getMessage());
            result.errors.add(new ExtractionError((String) null, "Fatal error: " + e.getMessage(), e));
            result.errorCount++;
        } finally {
            // Clean up temp file
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
        
        return result;
    }

    /**
     * Reads encryption info from the archive encryption block (for archives with encrypted headers).
     * This allows password verification BEFORE creating the decrypted temp file.
     * 
     * @param archivePath path to the archive
     * @return crypto info, or null if not found or error
     */
    private static Rar5ExtraCrypto readArchiveEncryptionInfo(String archivePath) {
        try {
            byte[] data = readFileHeader(archivePath, 200);
            if (data == null || data.length < Rar5Constants.RAR5_SIGNATURE.length + 20) {
                return null;
            }
            
            // Skip RAR5 signature
            int offset = Rar5Constants.RAR5_SIGNATURE.length;
            
            // Read header CRC (4 bytes)
            offset += 4;
            
            // Read header size
            VInt headerSize = VIntReader.read(data, offset, data.length);
            if (headerSize == null) return null;
            offset += headerSize.length;
            
            // Read block type
            VInt blockType = VIntReader.read(data, offset, data.length);
            if (blockType == null || blockType.value != Rar5Constants.BLOCK_TYPE_ARC_ENCRYPT) {
                return null;
            }
            offset += blockType.length;
            
            // Read block flags
            VInt blockFlags = VIntReader.read(data, offset, data.length);
            if (blockFlags == null) return null;
            offset += blockFlags.length;
            
            // ARC_ENCRYPT block structure:
            // - Encryption version (VInt)
            // - Encryption flags (VInt)
            // - KDF IterationExponent (1 byte)
            // - Salt (16 bytes)
            // - [Optional] Password check value (12 bytes) if flag 0x01 is set
            
            // Encryption version/algorithm
            VInt encVersion = VIntReader.read(data, offset, data.length);
            if (encVersion == null) return null;
            offset += encVersion.length;
            
            // Encryption flags
            VInt encFlags = VIntReader.read(data, offset, data.length);
            if (encFlags == null) return null;
            offset += encFlags.length;
            
            // KDF IterationExponent (1 byte)
            int kdfIterationExponent = data[offset] & 0xFF;
            offset += 1;
            
            // Salt (16 bytes)
            if (offset + 16 > data.length) return null;
            byte[] salt = Arrays.copyOfRange(data, offset, offset + 16);
            offset += 16;
            
            // Password check value (12 bytes) if present
            byte[] passwordCheck = null;
            boolean hasPasswordCheck = (encFlags.value & Rar5Constants.CRYPTO_FLAG_PASSWORD_CHECK) != 0;
            if (hasPasswordCheck && offset + 12 <= data.length) {
                passwordCheck = Arrays.copyOfRange(data, offset, offset + 12);
            }
            
            return Rar5ExtraCrypto.createForArchiveEncryption(
                encVersion.value,
                encFlags.value,
                kdfIterationExponent,
                salt,
                passwordCheck
            );
            
        } catch (Exception e) {
            return null;
        }
    }    
    
    /**
     * Extracts a single file from the archive.
     */
    private static void extractFile(Rar5FileBlock file, RandomAccessFile raf, Rar5Reader reader, String outputDir, String password, ExtractionResult result) throws Exception {
      extractFile(file, raf, reader, outputDir, password, result, true);
    }

    /**
     * Extracts a single file from the archive.
     * @param writeOutput if false, file is decoded but not written to disk (for solid archive skip)
     */
    private static void extractFile(Rar5FileBlock file, RandomAccessFile raf, Rar5Reader reader, String outputDir, String password, ExtractionResult result, boolean writeOutput) throws Exception {
        
        // Handle directories
        if (file.isDirectory()) {
            if (writeOutput) {
                File dir = pathBuilder.buildSafeDirPath(file.getFileName());
                dir.mkdirs();
            }
            result.successCount++;
            return;
        }
        
        // Handle empty files
        long start = file.getDataStart();
        long end = file.getDataEnd();
        long dataSize = end - start;
        
        if (dataSize == 0) {
            if (writeOutput) {
                File outFile = pathBuilder.buildSafePath(file.getFileName());
                outFile.getParentFile().mkdirs();
                outFile.createNewFile();
            }
            result.successCount++;
            return;
        }
        
        // Validate data position
        if (start >= end || end > raf.length()) {
            result.errors.add(buildError(file, "Invalid data position: " + start + "-" + end, null));
            result.errorCount++;
            return;
        }

        // Decompression bomb protection
        long unpackedSize = file.getUnpackedSize();
        if (maxCompressionRatio > 0 && dataSize > 0 && unpackedSize / dataSize > maxCompressionRatio) {
            result.errors.add(buildError(file, 
                "Compression ratio " + (unpackedSize / dataSize) + ":1 exceeds maximum allowed " + maxCompressionRatio + ":1", null));
            result.errorCount++;
            return;
        }

        // Get the input stream for decompression
        InputStream decompressInput;
        
        if (file.isEncrypted()) {
            // Encrypted: must load into memory for decryption
            if (password == null || password.isEmpty()) {
                result.errors.add(buildError(file, "File is encrypted but no password provided", null));
                result.errorCount++;
                return;
            }
            
            // Verify password first (if password check value is available)
            Rar5ExtraCrypto crypto = file.getCrypto();
            if (crypto != null && crypto.hasPasswordCheck()) {
                try {
                    boolean passwordOk = Rar5Crypto.verifyPassword(password, crypto);
                    if (!passwordOk) {
                        result.errors.add(buildError(file, "Wrong password", null));
                        result.errorCount++;
                        result.passwordStatus = 2; // BAD PASSWORD
                        return;
                    } else {
                        result.passwordStatus = 1; // GOOD PASSWORD
                    }
                } catch (Exception e) {
                    // Password verification failed, continue anyway
                }
            }
        
            // Create decrypting stream (no memory copy)
            raf.seek(start);
            InputStream boundedInput = new BoundedInputStream(raf, dataSize);
            decompressInput = reader.createDecryptingStream(file, boundedInput);
            if (decompressInput == null) {
                result.errors.add(buildError(file, "Decryption setup failed", null));
                result.errorCount++;
                return;
            }
        
        } else {
            // Non-encrypted: use BoundedInputStream directly (no memory copy)
            raf.seek(start);
            decompressInput = new BoundedInputStream(raf, dataSize);
        }
        
        if (writeOutput) {
            // --- Normal mode: decompress to file ---
            File outFile = pathBuilder.buildSafePath(file.getFileName());
            outFile.getParentFile().mkdirs();
            
            boolean success = decompressToFile(file, decompressInput, outFile);
            if (!success) {
                result.errors.add(buildError(file, "Decompression failed", null));
                result.errorCount++;
                return;
            }
            
            // Verify CRC32
            if (file.hasCRC()) {
                long calculatedCRC = calculateFileCRC(outFile);
                long expectedCRC = file.getCRC();
                
                boolean crcOk;
                if (file.isEncrypted() && !isEncryptedArchive) {
                    Rar5ExtraCrypto crypto = file.getCrypto();
                    byte[] hashKeyN16 = Rar5Crypto.deriveCrcHashKeyN16_Standard(password, crypto);
                    crcOk = Rar5Crypto.verifyCrcWithHMAC(calculatedCRC, expectedCRC, hashKeyN16);
                } else {
                    crcOk = (calculatedCRC == expectedCRC);
                }
                
                if (!crcOk) {
                    System.out.printf("CRC mismatch. Calculated: 0x%08X; expected: 0x%08X%n", calculatedCRC, expectedCRC);
                    outFile.delete();
                    throw new RarDecryptException("CRC mismatch - file may be corrupted.");
                }
            }
            
            result.successCount++;
            
        } else {
            // --- Skip mode (solid): decode without writing to disk ---
            // The stream must still be consumed to keep the decoder state
            decompressToNull(file, decompressInput);
        }
    }
    
    /**
     * Calculates CRC32 of a file without loading it entirely in memory.
     */
    private static long calculateFileCRC(File file) throws IOException {
        CRC32 crc32 = new CRC32();
        byte[] buffer = new byte[8192];
        try (FileInputStream fis = new FileInputStream(file)) {
            int read;
            while ((read = fis.read(buffer)) != -1) {
                crc32.update(buffer, 0, read);
            }
        }
        return crc32.getValue();
    }    
    
    
    /**
     * Decompresses from an InputStream directly to a file.
     * 
     * @param file the file block with compression info
     * @param input the input stream (compressed data)
     * @param outputFile the output file to write to
     * @return true if successful
     */
    private static boolean decompressToFile(Rar5FileBlock file, InputStream input, File outputFile) {
       ProgressOutputStream progressOut = null;

       try {
           int method = file.getCompressionMethod();
           long unpackedSize = file.getUnpackedSize();

           // Method 0 = store (no compression)
           if (method == Rar5Constants.COMPRESS_METHOD_STORE) {
               try (FileOutputStream fos = new FileOutputStream(outputFile);
                    BufferedOutputStream bos = new BufferedOutputStream(fos, 65536)) {
                   
                   OutputStream targetOut = showProgress
                       ? new ProgressOutputStream(bos, unpackedSize, file.getFileName())
                       : bos;

                   byte[] buffer = new byte[8192];
                   int read;
                   while ((read = input.read(buffer)) != -1) {
                       targetOut.write(buffer, 0, read);
                   }

                   if (targetOut instanceof ProgressOutputStream) {
                       ((ProgressOutputStream) targetOut).finish();
                   }
               }
               return true;
           }

           // All other compression methods 1 => 5
           if (sharedDecoder == null) {
               sharedDecoder = new Rar5LZDecoder();
           }

           if (!file.isSolid()) {
               sharedDecoder.reset();
           }

           byte[] properties = Rar5PropertyEncoder.encodeWindowSize(
               file.getWindowSize(),
               file.isSolid(),
               file.isV7()
           );

           sharedDecoder.setDecoderProperties(properties);

           try (FileOutputStream fos = new FileOutputStream(outputFile)) {
               OutputStream targetOut = showProgress 
                   ? new ProgressOutputStream(fos, unpackedSize, file.getFileName()) 
                   : fos;

               if (targetOut instanceof ProgressOutputStream) {
                   progressOut = (ProgressOutputStream) targetOut;
               }

               sharedDecoder.decode(input, targetOut, null, unpackedSize, null);

               if (progressOut != null) {
                   progressOut.finish();
               }
           }

           return true;

       } catch (RarCorruptedDataException e) {
           System.err.println("Corrupted data: " + e.getMessage());
           if (progressOut != null) {
               progressOut.finish();
           }
           return false;
           
       } catch (UnsupportedOperationException e) {
           System.err.println("Unsupported feature: " + e.getMessage());
           if (progressOut != null) {
               progressOut.finish();
           }
           return false;
           
       } catch (IOException e) {
           System.err.println("I/O error: " + e.getMessage());
           if (progressOut != null) {
               progressOut.finish();
           }
           return false;
           
       } catch (Exception e) {
           System.err.println("Error: " + e.getMessage());
           if (progressOut != null) {
               progressOut.finish();
           }
           return false;
       }
    }
   
    /**
     * Decompresses data from an InputStream without writing output.
     * Used for solid archives when skipping a file but needing to maintain decoder state.
     */
    private static void decompressToNull(Rar5FileBlock file, InputStream input) {
        try {
            int method = file.getCompressionMethod();
            long unpackedSize = file.getUnpackedSize();
            
            // Method 0 = Store (no compression) - just drain the stream
            if (method == Rar5Constants.COMPRESS_METHOD_STORE) {
                byte[] buf = new byte[8192];
                while (input.read(buf) != -1) {}
                return;
            }
            
            if (sharedDecoder == null) {
                sharedDecoder = new Rar5LZDecoder();
            }
            
            if (!file.isSolid()) {
                sharedDecoder.reset();
            }
            
            byte[] properties = Rar5PropertyEncoder.encodeWindowSize(
                  file.getWindowSize(),
                  file.isSolid(),
                  file.isV7()
            );
            
            sharedDecoder.setDecoderProperties(properties);
            
            // Decode into an OutputStream that discards everything
            OutputStream nullOut = new NullOutputStream();
            
            sharedDecoder.decode(input, nullOut, null, unpackedSize, null);
        } catch (Exception e) {
            System.err.println("Warning: failed to decode skipped solid file: " + file.getFileName());
        }
    }
    
    
    /**
     * Reads the first bytes of a file.
     */
    private static byte[] readFileHeader(String path, int size) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) {
            byte[] buffer = new byte[size];
            int read = fis.read(buffer);
            if (read < size) {
                return Arrays.copyOf(buffer, read);
            }
            return buffer;
        }
    }
    
    /**
     * Resets the shared decoder (useful for testing).
     */
    public static void resetDecoder() {
        if (sharedDecoder != null) {
            sharedDecoder.reset();
        }
    }
    

    // -------------------------------------------------------------------------
    // Multi-volume extraction (.partNN.rar sets)
    // -------------------------------------------------------------------------

    /**
     * Extracts a multi-volume RAR5 set. A single file may be split across
     * several volumes; its compressed-data chunks are concatenated and fed to
     * the decoder as one continuous stream (mirrors the RAR4 implementation).
     *
     * <p>Supported: plain archives and per-file encrypted archives (clear
     * headers). Header-encrypted (-hp) multi-volume sets are rejected earlier.</p>
     */
    private static ExtractionResult extractMultiVolume(File firstVolume, String outputDir,
            String password, String fileFilter, ExtractionResult result, boolean headerEncrypted) {

        java.util.List<File> volumes   = discoverVolumes(firstVolume);
        java.util.List<File> tempFiles = new java.util.ArrayList<>();
        System.out.println("Multi-volume archive: " + volumes.size() + " volume(s) found"
                + (headerEncrypted ? " (encrypted headers)" : ""));

        java.util.List<LogicalFile5> files =
                buildLogicalFiles(volumes, password, headerEncrypted, tempFiles);
        result.totalFiles = files.size();

        for (LogicalFile5 lf : files) {
            Rar5FileBlock head = lf.head;
            try {
                boolean isTarget = (fileFilter == null || fileFilter.equals(head.getFileName()));

                if (head.isDirectory()) {
                    if (isTarget) {
                        pathBuilder.buildSafeDirPath(head.getFileName()).mkdirs();
                        result.successCount++;
                    }
                    continue;
                }

                if (head.isSolid() && !isTarget) {
                    // Solid set: decode the skipped file to keep the decoder state
                    decompressToNull(head, openLogicalInput(lf, password));
                    continue;
                }
                if (!isTarget) {
                    continue;
                }

                File outFile = pathBuilder.buildSafePath(head.getFileName());
                if (outFile == null) {
                    result.errors.add(buildError(head, "Unsafe path", null));
                    result.errorCount++;
                    continue;
                }
                outFile.getParentFile().mkdirs();

                if (lf.unpackedSize == 0) {
                    outFile.createNewFile();
                    result.successCount++;
                    result.unpackedFiles.add(head.getFileName());
                    continue;
                }

                boolean ok = decompressToFile(head, openLogicalInput(lf, password), outFile);
                if (!ok) {
                    result.errors.add(buildError(head, "Decompression failed", null));
                    result.errorCount++;
                    continue;
                }

                // CRC32 check (full-file CRC; last chunk wins)
                if (lf.hasCrc) {
                    long calculatedCRC = calculateFileCRC(outFile);
                    long expectedCRC = lf.crc;
                    boolean crcOk;
                    if (head.isEncrypted() && !isEncryptedArchive) {
                        Rar5ExtraCrypto crypto = head.getCrypto();
                        byte[] hashKeyN16 = Rar5Crypto.deriveCrcHashKeyN16_Standard(password, crypto);
                        crcOk = Rar5Crypto.verifyCrcWithHMAC(calculatedCRC, expectedCRC, hashKeyN16);
                    } else {
                        crcOk = (calculatedCRC == expectedCRC);
                    }
                    if (!crcOk) {
                        System.out.printf("CRC mismatch. Calculated: 0x%08X; expected: 0x%08X%n",
                                calculatedCRC, expectedCRC);
                        outFile.delete();
                        result.errors.add(buildError(head, "CRC mismatch - file may be corrupted.", null));
                        result.errorCount++;
                        continue;
                    }
                }

                result.successCount++;
                result.unpackedFiles.add(head.getFileName());

            } catch (Exception e) {
                result.errors.add(buildError(head, "Exception during extraction", e));
                result.errorCount++;
                result.failedFiles.add(head.getFileName());
            }
        }

        // Clean up per-volume temp files created for header decryption
        for (File t : tempFiles) {
            try { t.delete(); } catch (Exception ignore) { /* best effort */ }
        }
        return result;
    }

    /**
     * Opens the concatenated compressed-data stream for a logical file,
     * wrapping it in a single AES-CBC decrypting stream when the file is
     * per-file encrypted (the cipher then spans volume boundaries correctly).
     */
    private static InputStream openLogicalInput(LogicalFile5 lf, String password) throws Exception {
        InputStream in = new Rar5MultiVolumeInputStream(lf.segments);
        if (lf.head.isEncrypted()) {
            InputStream dec = lf.reader.createDecryptingStream(lf.head, in);
            if (dec == null) {
                throw new RarDecryptException("Decryption setup failed");
            }
            in = dec;
        }
        return in;
    }

    /**
     * Discovers all volumes of a .partNN.rar set, starting from the given
     * volume (e.g. archive.part01.rar, archive.part02.rar, ...).
     */
    private static java.util.List<File> discoverVolumes(File firstVolume) {
        java.util.List<File> vols = new java.util.ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("(?i)(.*[^0-9])([0-9]+)(\\.rar)$").matcher(firstVolume.getName());
        if (!m.matches()) {
            vols.add(firstVolume);
            return vols;
        }
        String prefix = m.group(1);
        int    width  = m.group(2).length();
        int    n      = Integer.parseInt(m.group(2));
        String suffix = m.group(3);
        File   dir    = firstVolume.getParentFile();
        // Rewind to the lowest existing volume so opening any part works.
        while (n > 0) {
            File prev = new File(dir, prefix + String.format("%0" + width + "d", n - 1) + suffix);
            if (!prev.exists()) break;
            n--;
        }
        while (true) {
            File vf = new File(dir, prefix + String.format("%0" + width + "d", n) + suffix);
            if (!vf.exists()) break;
            vols.add(vf);
            n++;
        }
        return vols;
    }

    /** A file reconstructed from one or more split chunks across volumes. */
    private static class LogicalFile5 {
        Rar5FileBlock head;          // first chunk: name, size, method, crypto, flags
        Rar5Reader    reader;        // reader of the head's volume (for decryption)
        long          unpackedSize;  // full unpacked size (from the first chunk)
        long          crc;           // full-file CRC (last chunk wins)
        boolean       hasCrc;
        final java.util.List<Rar5MultiVolumeInputStream.Segment> segments =
                new java.util.ArrayList<>();
    }

    /**
     * Parses every volume and groups split chunks into logical files. A file
     * block flagged "continues from previous volume" appends a data segment to
     * the current logical file; any other block starts a new one.
     */
    private static java.util.List<LogicalFile5> buildLogicalFiles(java.util.List<File> volumes,
            String password, boolean headerEncrypted, java.util.List<File> tempFiles) {
        java.util.List<LogicalFile5> result = new java.util.ArrayList<>();
        LogicalFile5 current = null;
        for (File vol : volumes) {
            // For encrypted headers, decrypt this volume to a temp file first.
            // The temp holds decrypted headers; the file data inside it stays
            // encrypted and is decrypted later, as one stream per logical file.
            File source = vol;
            if (headerEncrypted) {
                try {
                    File tmp = File.createTempFile("unrar5j_mv_", ".rar");
                    tmp.deleteOnExit();
                    new Rar5HeaderDecryptor(password)
                            .decryptToFile(vol.getAbsolutePath(), tmp.getAbsolutePath());
                    tempFiles.add(tmp);
                    source = tmp;
                } catch (Exception e) {
                    continue;
                }
            }

            Rar5Reader reader = new Rar5Reader(password);
            if (!reader.read(source)) continue;
            for (Rar5FileBlock fb : reader.getFileBlocks()) {
                long size = fb.getDataEnd() - fb.getDataStart();
                if (fb.isPreviousVolume() && current != null) {
                    // Continuation chunk: append data and adopt this chunk's
                    // CRC. RAR5 stores a cumulative CRC per split part, so the
                    // last chunk carries the full-file CRC (last chunk wins).
                    current.segments.add(new Rar5MultiVolumeInputStream.Segment(
                            source, fb.getDataStart(), size));
                    current.crc    = fb.getCRC();
                    current.hasCrc = fb.hasCRC();
                } else {
                    current = new LogicalFile5();
                    current.head         = fb;
                    current.reader       = reader;
                    current.unpackedSize = fb.getUnpackedSize();
                    current.crc          = fb.getCRC();
                    current.hasCrc       = fb.hasCRC();
                    current.segments.add(new Rar5MultiVolumeInputStream.Segment(
                            source, fb.getDataStart(), size));
                    result.add(current);
                }
            }
        }
        return result;
    }

    /**
     * Builds an {@link ExtractionError} from a RAR5 file block, keeping the
     * RAR5-to-common mapping inside the RAR5 layer.
     */
    private static ExtractionError buildError(Rar5FileBlock file, String message, Exception ex) {
        return new ExtractionError(
                file.getFileName(),
                file.getUnpackedSize(),
                file.getCompressionMethod(),
                file.isV7(),
                file.isSolid(),
                file.isEncrypted(),
                message,
                ex);
    }


}
