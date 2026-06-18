# unrar5j

A pure Java extractor for RAR archives, handling both RAR4 and RAR5, with no
native dependencies.

```
                         ___
  _  _ _ _  _ _ __ _ _ _| __| (_)
 | || | ' \| '_/ _` | '_|__ \ | |
 \__,_|_|_||_| \__,_|_| |___//__|

```

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/)

## Features

- Pure Java, no native libraries or JNI
- RAR4 and RAR5, detected automatically
- AES decryption, including encrypted file names and headers
- Solid archives and multi-volume sets
- DELTA, E8, E8E9 and ARM filters
- CRC32 verification on extracted files
- Path traversal protection on output names

## Requirements

- Java 8 or higher
- No external dependencies

## Command line usage

The `Unrar5j` entry point detects the format (RAR4 or RAR5) on its own, so
you never have to say which one it is.

```bash
java -jar unrar5j.jar myarchive.rar [-o outputDir] [-p password] [-f filename]
```

### Examples

```bash
# Extract to the current directory
java -jar unrar5j.jar myarchive.rar

# Extract to a chosen directory
java -jar unrar5j.jar myarchive.rar -o ./output

# Extract an encrypted archive
java -jar unrar5j.jar encrypted.rar -p mysecretpassword

# Extract a single entry by its path inside the archive
java -jar unrar5j.jar myarchive.rar -f "docs/report with spaces.pdf"
```

For a multi-volume set, pass any volume (for example part01.rar). The tool finds
the first volume and walks forward through the rest.

## Library usage

```java
import be.stef.rar.Unrar5j;
import be.stef.rar.ExtractionResult;

// Extract without a password
ExtractionResult result = Unrar5j.extract("archive.rar", "output", null);

// Extract with a password
ExtractionResult enc = Unrar5j.extract("encrypted.rar", "output", "mypassword");

// Extract a single entry
ExtractionResult one = Unrar5j.extract("archive.rar", "output", null, "docs/report.pdf");

System.out.println("Extracted: " + result.successCount + "/" + result.totalFiles);
if (result.errorCount > 0) {
    result.print();
}
```

A few things worth knowing when embedding the library:

- `Unrar5j.detectFormat(path)` returns FORMAT_RAR4, FORMAT_RAR5 or FORMAT_UNKNOWN.
- `Unrar5j.isEncrypted(path)` tells you whether to prompt for a password.
- After extraction, `result.passwordStatus` is 2 when the password was wrong.
- Set `Unrar4j.showProgress = false` and `Unrar5j.showProgress = false` to silence the console progress bar.

## Supported features

| Feature                     | RAR4    | RAR5    |
|-----------------------------|---------|---------|
| Store (no compression)      | Yes     | Yes     |
| Compressed extraction       | Yes     | Yes     |
| Solid archives              | Yes     | Yes     |
| Multi-volume sets           | Yes     | Yes     |
| AES encryption (data)       | Yes     | Yes     |
| Encrypted headers and names | Yes     | Yes     |
| Encrypted multi-volume      | Yes     | Yes     |
| CRC32 verification          | Yes     | Yes     |
| DELTA / E8 / E8E9 filters   | Yes     | Yes     |
| ARM filter                  | n/a     | Yes     |
| PPMd method                 | No      | n/a     |
| Recovery records            | No      | No      |
| BLAKE2 hash verification    | n/a     | No      |

## What is not supported

- Creating or modifying archives. This is a reader only.
- The RAR4 PPMd method (0x35).
- The rarer RAR4 VM filters (ITANIUM, RGB, AUDIO, UPCASE).
- Archive comments and recovery records are skipped rather than exposed.

## Remarks

Unrar5j may still contain bugs. If you find one, please let me know and, if possible, send me a link to the archive.

## Building

```bash
# Compile
javac -encoding UTF-8 -d bin $(find be -name "*.java")

# Create an executable JAR
jar cfe unrar5j.jar be.stef.rar.Unrar5j -C bin .
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and the NOTICE file.

This is a decompression-only implementation. The RAR formats were created by
Alexander Roshal, and the RAR compression algorithm is proprietary; this code
must not be used to build a RAR-compatible compressor.

## Author

Stéphane BURY

