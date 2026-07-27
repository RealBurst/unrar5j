# unrar5j

A pure Java RAR extractor (RAR4 and RAR5) with no native dependencies.

```
                        ___
 _  _ _ _  _ _ __ _ _ _| __| (_)
| || | ' \| '_/ _` | '_|__ \ | |
\__,_|_|_||_| \__,_|_| |___//__|

```

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/RealBurst/unrar5j/blob/main/LICENSE) [![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/) [![Maven Central](https://img.shields.io/badge/Maven%20Central-io.github.realburst-blue.svg)](https://central.sonatype.com/artifact/io.github.realburst/unrar5j)

## Features

- **Pure Java** - No native libraries or JNI required
- **Zero dependencies** - No external libraries required, native or otherwise
- **Lightweight** - ~12,000 lines of code covering full RAR4 and RAR5 support
- **RAR4 and RAR5** - Automatic format detection, no configuration needed
- **Encryption** - AES-128 (RAR4) and AES-256 (RAR5) decryption
- **Header Encryption** - Support for encrypted file names and headers
- **Compression** - LZ77-based decompression with Huffman coding
- **Filters** - DELTA, E8, E8E9 (x86), ARM (RAR5) filter support
- **Solid Archives** - Proper handling of solid compression
- **Multi-volume archives** - Extraction across split .partNN.rar sets
- **CRC32 Verification** - Integrity check on extracted files
- **BLAKE2sp Verification** - Stronger integrity check when present in RAR5 archives

## Requirements

- Java 8 or higher
- No external dependencies

## Installation

### Maven

```xml
<dependency>
  <groupId>io.github.realburst</groupId>
  <artifactId>unrar5j</artifactId>
  <version>2.0.3</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.github.realburst:unrar5j:2.0.3'
```

## Command Line Usage

```
java -jar unrar5j.jar <archive.rar> [-o outputDir] [-p password] [-f filename]
```

The archive format (RAR4 or RAR5) is detected automatically.

### Options

| Option | Description |
| --- | --- |
| `-o <dir>` | Extract to specified directory (default: current directory) |
| `-p <password>` | Password for encrypted archives |
| `-f <filename>` | Extract only this specific file from the archive |

### Examples

```
# Extract to current directory
java -jar unrar5j.jar archive.rar

# Extract to a specific directory
java -jar unrar5j.jar archive.rar -o ./output

# Extract an encrypted archive
java -jar unrar5j.jar encrypted.rar -p mysecretpassword

# Extract a single file from an archive
java -jar unrar5j.jar archive.rar -f "path/to/document.pdf"

# Combine options
java -jar unrar5j.jar encrypted.rar -o ./output -p secret -f path/to/myfile.txt
```

## Library Usage

### Extract an archive

```java
import be.stef.rar.Unrar5j;
import be.stef.rar.ExtractionResult;

// Extract without password (RAR4 or RAR5 detected automatically)
ExtractionResult result = Unrar5j.extract("archive.rar", "./output", null);

// Extract with password
ExtractionResult result = Unrar5j.extract("encrypted.rar", "./output", "mypassword");

// Check results
System.out.println("Extracted: " + result.successCount + "/" + result.totalFiles);
if (result.errorCount > 0) {
    result.print();  // Print detailed error report
}

// Check overall success
if (result.isSuccess()) {
    System.out.println("All files extracted successfully.");
}
```

### Extract a single file

```java
import be.stef.rar.Unrar5j;
import be.stef.rar.ExtractionResult;

ExtractionResult result = Unrar5j.extract("archive.rar", "./output", null, "path/to/document.pdf");
result.print();
```

### Detect archive format

```java
import be.stef.rar.Unrar5j;

int format = Unrar5j.detectFormat("archive.rar");
if (format == Unrar5j.FORMAT_RAR5) {
    System.out.println("RAR5 archive");
} else if (format == Unrar5j.FORMAT_RAR4) {
    System.out.println("RAR4 archive");
} else {
    System.out.println("Unknown format");
}
```

### Check if password is required

```java
import be.stef.rar.Unrar5j;

if (Unrar5j.isEncrypted("archive.rar")) {
    System.out.println("Password required");
}
```

## ExtractionResult fields

| Field | Type | Description |
| --- | --- | --- |
| `successCount` | `int` | Number of successfully extracted files |
| `errorCount` | `int` | Number of files that failed to extract |
| `totalFiles` | `int` | Total number of files in the archive |
| `unpackedFiles` | `ArrayList<String>` | List of successfully extracted file names |
| `failedFiles` | `ArrayList<String>` | List of failed file names |
| `passwordStatus` | `int` | 0=N/A, 1=password OK, 2=wrong password |
| `errors` | `List<ExtractionError>` | Detailed error list |

## Supported Features

| Feature | RAR4 | RAR5 |
| --- | --- | --- |
| Store (no compression) | Yes | Yes |
| Compressed extraction | Yes | Yes |
| Solid archives | Yes | Yes |
| Multi-volume sets | Yes | Yes |
| AES encryption (data) | Yes | Yes |
| Encrypted headers and names | Yes | Yes |
| Encrypted multi-volume | Yes | Yes |
| CRC32 verification | Yes | Yes |
| DELTA / E8 / E8E9 filters | Yes | Yes |
| ARM filter | No | Yes |
| BLAKE2sp verification | No | Yes |
| PPMd method | No | n/a |
| Recovery records | No | No |

## What is not supported

- Creating or modifying archives. This is a reader only.
- The RAR4 PPMd method (0x35).
- The rarer RAR4 VM filters (ITANIUM, RGB, AUDIO).
- Archive comments and recovery records are skipped rather than exposed.

## Building

```
# Windows — list all sources then compile
dir /s /b src\*.java > sources.txt
javac -d bin @sources.txt

# Linux / macOS
find src -name "*.java" | xargs javac -d bin

# Create JAR
jar cfe unrar5j.jar be.stef.rar.Unrar5j -C bin .
```

## License

Apache License 2.0 - See [LICENSE](https://github.com/RealBurst/unrar5j/blob/main/LICENSE)

## Author

**Stephane BURY**

## Acknowledgments

7-Zip by Igor Pavlov was a valuable reference for troubleshooting some decompression challenges.