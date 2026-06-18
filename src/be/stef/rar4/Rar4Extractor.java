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
package be.stef.rar4;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;

import be.stef.rar.ExtractionError;
import be.stef.rar.ExtractionResult;
import be.stef.rar.util.BoundedInputStream;
import be.stef.rar.util.CrcOutputStream;
import be.stef.rar.util.ProgressOutputStream;
import be.stef.rar.util.SafePathBuilder;
import be.stef.rar4.blocks.Rar4FileBlock;
import be.stef.rar4.decompress.Rar4Decompressor;
import be.stef.rar4.decompress.Rar4DecompressorRegistry;

/**
 * High-level API for extracting RAR4 archives.
 *
 * <p>Extraction is implemented incrementally by compression method:</p>
 * <ul>
 *   <li>Phase 1 : Store (0x30) - no compression</li>
 *   <li>Phase 2 : LZ77 (0x31-0x34) - future</li>
 *   <li>Phase 3 : PPMd (0x35) - future</li>
 * </ul>
 *
 * @author Stef
 * @since 1.0
 */
public class Rar4Extractor {
    public static boolean  showProgress      = true;
    public static SafePathBuilder pathBuilder = null;
    public static long     maxCompressionRatio = 1000;
    private static final Rar4DecompressorRegistry registry = new Rar4DecompressorRegistry();
    
    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public static ExtractionResult extract(String archivePath, String outputDir, String password) {
        return extract(archivePath, outputDir, password, null);
    }

    public static synchronized ExtractionResult extract(String archivePath, String outputDir, String password, String fileFilter) {
        ExtractionResult result = new ExtractionResult();
        result.archiveName = archivePath;

        try {
            File archiveFile = new File(archivePath);
            if (!archiveFile.exists()) {
                System.err.println("Archive [" + archiveFile.getCanonicalPath() + "] not found!");
                return result;
            }

            File outDir = new File(outputDir);
            if (!outDir.exists()) outDir.mkdirs();

            pathBuilder = new SafePathBuilder(outDir);

            // Parse headers
            Rar4HeaderParser parser = new Rar4HeaderParser();
            if (!parser.parse(archiveFile, password)) {
                System.err.println("Failed to parse RAR4 archive: " + archivePath);
                return result;
            }
            
            if (parser.isVolume()) {
               return extractMultiVolume(archiveFile, outDir, password, fileFilter, result);
            }

            boolean archiveIsSolid = parser.isSolid();
            
            List<Rar4FileBlock> fileBlocks = parser.getFileBlocks();
            result.totalFiles = fileBlocks.size();


            try (RandomAccessFile raf = new RandomAccessFile(archiveFile, "r")) {
                for (Rar4FileBlock file : fileBlocks) {
                    try {
                        boolean isTarget = (fileFilter == null || fileFilter.equals(file.getFileName()));

                        if (!isTarget) continue;

                        if (file.isDirectory()) {
                            createDirectory(file, outDir);
                            result.successCount++;
                            continue;
                        }
                        
                        // Also skip entries with packedSize=0 and unpackedSize=0
                        if (file.getPackedSize() == 0 && file.getUnpackedSize() == 0) {
                            continue;
                        }
                        
                        boolean ok = extractFile(raf, file, outDir, password);
                        if (ok) {
                            result.successCount++;
                        } else {
                            result.errors.add(new ExtractionError(file.getFileName(), "Extraction failed"));
                        }

                    } catch (Exception e) {
                        result.errors.add(new ExtractionError(file.getFileName(), e.getMessage()));
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Extraction error: " + e.getMessage());
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // File extraction
    // -------------------------------------------------------------------------

    private static boolean extractFile(RandomAccessFile raf, Rar4FileBlock file, File outDir, String password) throws IOException {
       int method = file.getCompressionMethod();
       int version = file.getRequiredVersion();

       if (file.getPackedSize() > 0 && file.getUnpackedSize() > 0) {
          long ratio = file.getUnpackedSize() / file.getPackedSize();
          if (ratio > maxCompressionRatio) {
              System.err.println("Suspicious compression ratio for: " + file.getFileName());
              return false;
          }
       }

       File outputFile = pathBuilder.buildSafePath(file.getFileName());
       if (outputFile == null) {
          System.err.println("Unsafe path rejected: " + file.getFileName());
          return false;
       }
       if (outputFile.getParentFile() != null) outputFile.getParentFile().mkdirs();


       Rar4Decompressor decompressor;
       try {
          decompressor = registry.resolve(method, version);
       } catch (Exception e) {
          System.err.println("Compression method 0x" + Integer.toHexString(method).toUpperCase() + " not yet supported: " + file.getFileName());
          return false;
       }

       // Solid: preserve decompressor state across files.
       decompressor.resetState(file.isSolid());
    
       CRC32 crc = new CRC32();
       ProgressOutputStream progressOut = null;

       raf.seek(file.getDataStart());

       try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
          BoundedInputStream bounded = new BoundedInputStream(raf, file.getPackedSize());

          InputStream source = bounded;
          if (file.isEncrypted()) {
              if (password == null || password.isEmpty()) {
                  System.err.println("Password required for: " + file.getFileName());
                  if (progressOut != null) progressOut.finish();
                  return false;
              }
              byte[] salt = file.getSalt();
              if (salt == null) {
                  System.err.println("Encrypted file without salt: " + file.getFileName());
                  if (progressOut != null) progressOut.finish();
                  return false;
              }
              try {
                  javax.crypto.Cipher cipher = be.stef.rar4.crypto.Rar4Crypto.buildDecipher(password, salt);
                  source = new be.stef.rar4.crypto.Rar4DecryptInputStream(bounded, cipher);
              } catch (Exception e) {
                  System.err.println("Decryption init failed for " + file.getFileName() + ": " + e.getMessage());
                  if (progressOut != null) progressOut.finish();
                  return false;
              }
          }
          
          OutputStream out = showProgress ? new ProgressOutputStream(bos, file.getUnpackedSize(), file.getFileName()) : bos;

          if (out instanceof ProgressOutputStream) progressOut = (ProgressOutputStream) out;

          // CRC accumulator wrapped around the output (bulk-capable)
          OutputStream crcOut = new CrcOutputStream(out, crc);

          try {
             decompressor.decompress(source, crcOut, file);
          } catch (Exception e) {
             System.err.println("Decompress error for " + file.getFileName() + " : " + e.getClass().getSimpleName() + " : " + e.getMessage());
             if (progressOut != null) progressOut.finish();
             return false;
          }
          
          raf.seek(file.getDataStart() + file.getPackedSize());
          
          if (progressOut != null) progressOut.finish();

       } catch (IOException e) {
          if (progressOut != null) progressOut.finish();
          throw e;
       }

       long computed = crc.getValue();
       long expected = file.getCrc32();
       if (computed != expected) {
          System.err.printf("CRC32 mismatch for %s : expected %08X, got %08X%n", file.getFileName(), expected, computed);
          return false;
       }

       return true;
    }

    private static ExtractionResult extractMultiVolume(File firstVolume, File outDir, String password, String fileFilter, ExtractionResult result) {
      java.util.List<File> volumes = discoverVolumes(firstVolume);
      java.util.List<LogicalFile> files = buildLogicalFiles(volumes, password);
      result.totalFiles = files.size();

      for (LogicalFile lf : files) {
          try {
              Rar4FileBlock head = lf.head;
              if (fileFilter != null && !fileFilter.equals(head.getFileName())) continue;

              if (head.isDirectory()) {
                  createDirectory(head, outDir);
                  result.successCount++;
                  continue;
              }
              if (lf.unpackedSize == 0) continue;

              File outputFile = pathBuilder.buildSafePath(head.getFileName());
              if (outputFile == null) { result.errors.add(new ExtractionError(head.getFileName(), "Unsafe path")); continue; }
              if (outputFile.getParentFile() != null) outputFile.getParentFile().mkdirs();

              Rar4Decompressor decompressor = registry.resolve(head.getCompressionMethod(), head.getRequiredVersion());
              decompressor.resetState(head.isSolid());

              CRC32 crc = new CRC32();
              try (java.io.BufferedOutputStream bos = new java.io.BufferedOutputStream(new FileOutputStream(outputFile))) {
                  OutputStream out = showProgress
                          ? new ProgressOutputStream(bos, lf.unpackedSize, head.getFileName()) : bos;
                  OutputStream crcOut = new CrcOutputStream(out, crc);

                  InputStream source = new Rar4MultiVolumeInputStream(lf.segments);
                  if (head.isEncrypted()) {
                      byte[] salt = head.getSalt();
                      javax.crypto.Cipher cipher = be.stef.rar4.crypto.Rar4Crypto.buildDecipher(password, salt);
                      source = new be.stef.rar4.crypto.Rar4DecryptInputStream(source, cipher);
                  }

                  decompressor.decompress(source, crcOut, head);
                  if (out instanceof ProgressOutputStream) ((ProgressOutputStream) out).finish();
              }

              if (crc.getValue() != (lf.crc & 0xFFFFFFFFL)) {
                  System.err.printf("CRC32 mismatch for %s : expected %08X, got %08X%n",
                          head.getFileName(), lf.crc, crc.getValue());
                  result.errors.add(new ExtractionError(head.getFileName(), "CRC mismatch"));
              } else {
                  result.successCount++;
              }
          } catch (Exception e) {
              result.errors.add(new ExtractionError(lf.head.getFileName(), e.getMessage()));
          }
      }
      return result;
   }

    /**
     * Discovers all volumes of a .partNN.rar set, starting from the given volume.
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
        while (true) {
            File vf = new File(dir, prefix + String.format("%0" + width + "d", n) + suffix);
            if (!vf.exists()) break;
            vols.add(vf);
            n++;
        }
        return vols;
    }
    
    private static class LogicalFile {
       Rar4FileBlock head;   // first chunk: name, size, salt, method, flags
       long crc;             // CRC of the last chunk (= full-file CRC)
       long unpackedSize;
       final java.util.List<Rar4MultiVolumeInputStream.Segment> segments = new java.util.ArrayList<>();
    }

    private static java.util.List<LogicalFile> buildLogicalFiles(java.util.List<File> volumes, String password) {
       java.util.List<LogicalFile> result = new java.util.ArrayList<>();
       LogicalFile current = null;
       for (File vol : volumes) {
           Rar4HeaderParser parser = new Rar4HeaderParser();
           if (!parser.parse(vol, password)) continue;
           for (Rar4FileBlock fb : parser.getFileBlocks()) {
               if (fb.isContinuedFromPrev() && current != null) {
                   current.segments.add(new Rar4MultiVolumeInputStream.Segment(
                           vol, fb.getDataStart(), fb.getPackedSize()));
                   current.crc = fb.getCrc32();   // last chunk wins
               } else {
                   current = new LogicalFile();
                   current.head         = fb;
                   current.unpackedSize = fb.getUnpackedSize();
                   current.crc          = fb.getCrc32();
                   current.segments.add(new Rar4MultiVolumeInputStream.Segment(
                           vol, fb.getDataStart(), fb.getPackedSize()));
                   result.add(current);
               }
           }
       }
       return result;
    }
    
    
    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static void createDirectory(Rar4FileBlock file, File outDir) {
       try {
          if(file.isDirectory()) {
             File f = new File(pathBuilder.getBaseDir() + File.separator + file.getFileName());
             if(f.exists()) {
                return;
             }
          }
           File dir = pathBuilder.buildSafePath(file.getFileName());
           if (dir != null && !dir.exists()) dir.mkdirs();
       } catch (IOException e) {
           System.err.println("Failed to create directory: " + file.getFileName());
       }
    }
    
    
    /**
     * Checks if an archive requires a password (encrypted headers or first file encrypted).
     */
    public static boolean isEncrypted(String archivePath) {
        try {
            Rar4HeaderParser parser = new Rar4HeaderParser();
            if (!parser.parse(new File(archivePath))) return false;
            if (parser.hasEncryptedHeaders()) return true;
            List<Rar4FileBlock> files = parser.getFileBlocks();
            return !files.isEmpty() && files.get(0).isEncrypted();
        } catch (Exception e) {
            return false;
        }
    }

}