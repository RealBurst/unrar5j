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
import be.stef.rar5.blocks.Rar5FileBlock;
import be.stef.rar5.crypto.Rar5Crypto;
import be.stef.rar5.decompress.Rar5LZDecoder;
import be.stef.rar5.decompress.Rar5PropertyEncoder;
import be.stef.rar5.exceptions.Rar5CorruptedDataException;
import be.stef.rar5.exceptions.Rar5DecryptException;
import be.stef.rar5.extra.Rar5ExtraCrypto;
import be.stef.rar5.util.BoundedInputStream;
import be.stef.rar5.util.ProgressOutputStream;
import be.stef.rar5.util.SafePathBuilder;
import be.stef.rar5.util.VInt;
import be.stef.rar5.util.VIntReader;


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
public class Unrar5j {
    private static Rar5LZDecoder sharedDecoder = null;
    public static boolean showProgress = true;    
    public static boolean isEncryptedArchive;
    public static SafePathBuilder pathBuilder;
    
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
        ExtractionResult result = new ExtractionResult();
        File tempFile = null;
        isEncryptedArchive = false;
        
        result.archiveName = archivePath;
              
        try {
            File archiveFile = new File(archivePath);
            if (!archiveFile.exists()) {
                return result;
            }
            
            File outDir = new File(outputDir);
            if (!outDir.exists()) {
                outDir.mkdirs();
            }
            
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
                        result.passwordStatut = passwordOk ? 1 : 2;
                        if (!passwordOk) {
                            System.out.println("ERROR: Wrong password for encrypted archive!");
                            return result;
                        }
                    } catch (Exception e) {
                        // Password verification failed, continue anyway
                    }
                }
                
                String tempPath = archivePath.replace(".rar", "_dec.rar");
                Rar5HeaderDecryptor decryptor = new Rar5HeaderDecryptor(password);
                decryptor.decryptToFile(archivePath, tempPath);
                
                tempFile = new File(tempPath);
                archiveFile = tempFile;
            }
         
            // Step 2: Read archive headers (small, stays in memory)
            Rar5Reader reader = new Rar5Reader(password);
            if (!reader.read(archiveFile)) {
                return result;
            }

            List<Rar5FileBlock> fileBlocks = reader.getFileBlocks();
            result.totalFiles = fileBlocks.size();

            // Step 3: Extract each file using RandomAccessFile
            try (RandomAccessFile raf = new RandomAccessFile(archiveFile, "r")) {
                for (Rar5FileBlock file : fileBlocks) {
                    try {
                        extractFile(file, raf, reader, outputDir, password, result);
                        result.unpackedFiles.add(file.getFileName());
                    } catch (Exception e) {
                        result.errors.add(new ExtractionError(file, "Exception during extraction", e));
                        result.errorCount++;
                        result.failedFiles.add(file.getFileName());
                    }
                }
            }            
            
        } catch (Exception e) {
            // Fatal error
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
        // Handle directories
        if (file.isDirectory()) {
            File dir = new File(outputDir, file.getFileName());
            dir.mkdirs();
            result.successCount++;
            return;
        }
        
        // Handle empty files
        long start = file.getDataStart();
        long end = file.getDataEnd();
        long dataSize = end - start;
        
        if (dataSize == 0) {
            File outFile = pathBuilder.buildSafePath(file.getFileName());
            outFile.getParentFile().mkdirs();
            outFile.createNewFile();
            result.successCount++;
            return;
        }
        
        // Validate data position
        if (start >= end || end > raf.length()) {
            result.errors.add(new ExtractionError(file, "Invalid data position: " + start + "-" + end, null));
            result.errorCount++;
            return;
        }
        
        // Prepare output file
        File outFile = new File(outputDir, file.getFileName());
        outFile.getParentFile().mkdirs();
        
        // Get the input stream for decompression
        InputStream decompressInput;
        
        if (file.isEncrypted()) {
            // Encrypted: must load into memory for decryption
            if (password == null || password.isEmpty()) {
                result.errors.add(new ExtractionError(file, "File is encrypted but no password provided", null));
                result.errorCount++;
                return;
            }
            
            // Verify password first (if password check value is available)
            Rar5ExtraCrypto crypto = file.getCrypto();
            if (crypto != null && crypto.hasPasswordCheck()) {
                try {
                    boolean passwordOk = Rar5Crypto.verifyPassword(password, crypto);
                    if (!passwordOk) {
                        result.errors.add(new ExtractionError(file, "Wrong password", null));
                        result.errorCount++;
                        result.passwordStatut = 2; // BAD PASSWORD
                        return;
                    } else {
                        result.passwordStatut = 1; // GOOD PASSWORD
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
                result.errors.add(new ExtractionError(file, "Decryption setup failed", null));
                result.errorCount++;
                return;
            }
        
        } else {
            // Non-encrypted: use BoundedInputStream directly (no memory copy)
            raf.seek(start);
            decompressInput = new BoundedInputStream(raf, dataSize);
        }
        
        // Decompress directly to file
        boolean success = decompressToFile(file, decompressInput, outFile);
        if (!success) {
            result.errors.add(new ExtractionError(file, "Decompression failed", null));
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
                outFile.delete(); // Remove corrupted file
                throw new Rar5DecryptException("CRC mismatch - file may be corrupted.");
            }
        }
        
        result.successCount++;
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

           // Toutes les autres méthodes de compression 1 => 5
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

       } catch (Rar5CorruptedDataException e) {
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
           if (progressOut != null) {
               progressOut.finish();
           }
           return false;
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

    
    private static void printBannerOld() {
       System.out.println("               ___");
       System.out.println("  _ _ __ _ _ _| __| (_)");
       System.out.println(" | '_/ _` | '_|__ \\ | |");
       System.out.println(" |_| \\__,_|_| |___//__|  v2026.01.23");
       System.out.println("  Stéphane BURY - Apache 2.0");
       System.out.println();
    }
    
    private static void printBanner() {
       System.out.println("                          ___");
       System.out.println("  _  _ _ _  _ _ __ _ _ _| __| (_)");
       System.out.println(" | || | ' \\| '_/ _` | '_|__ \\ | |");
       System.out.println(" \\__,_|_|_||_| \\__,_|_| |___//__|  v2026.01.23");
       System.out.println("    Stéphane BURY - Apache 2.0");
       System.out.println();
    }
    
    public static void main(String[] args) {
      printBanner();
      if (args.length < 2) {
          System.out.println("Usage: java Unrar5j <archive.rar> <outputDir> [password]");
          return;
      }
      String archivePath = args[0];
      String outputDir = args[1];
      String password = (args.length > 2) ? args[2] : null;
      
      SimpleDateFormat df = new SimpleDateFormat("dd/MM:ss - HH:mm:ss");
      Date start = new Date();
      System.out.println("Démarrage de la décryption et décompression at "+df.format(start)+" ...");

      pathBuilder = new SafePathBuilder(new File(outputDir));
     
      ExtractionResult result = extract(archivePath, outputDir, password);
      result.print();
     
      Date fin = new Date();
      System.out.println("Fin de la décryption et décompression at "+df.format(fin)+" ...");
      System.out.println("Durée totale "+df.format(new Date(fin.getTime()-start.getTime())));
    }


}
