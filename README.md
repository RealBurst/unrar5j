# rar5j

A pure Java RAR5 extractor with no native dependencies.

```
               ___
  _ _ __ _ _ _| __| (_)
 | '_/ _` | '_|__ \\ | |
 |_| \\__,_|_| |___//__| 
```

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/)

## Features

- **Pure Java** — No native libraries or JNI required
- **RAR5 Format** — Full support for the modern RAR5 archive format
- **Encryption** — AES-256 decryption with PBKDF2-HMAC-SHA256 key derivation
- **Header Encryption** — Support for encrypted file names and headers
- **Compression** — LZ77-based decompression with Huffman coding
- **Filters** — DELTA, E8, E8E9 (x86), and ARM filter support
- **Solid Archives** — Proper handling of solid compression
- **CRC32 Verification** — Integrity check on extracted files

## Requirements

- Java 8 or higher
- No external dependencies

## Command Line Usage

```bash
java -jar rar5j.jar <archive.rar> <output_directory> [password]
```

### Examples

```bash
# Extract archive
java -jar rar5j.jar myarchive.rar ./output

# Extract encrypted archive
java -jar rar5j.jar encrypted.rar ./output mysecretpassword
```

### Linux/macOS

```bash
chmod +x rar5j
./rar5j myarchive.rar ./output
```

## Library Usage

### Extract an archive

```java
import be.stef.rar5.Rar5j;
import be.stef.rar5.ExtractionResult;

// Extract without password
ExtractionResult result = Rar5j.extract(
    "archive.rar",
    "output_directory",
    null
);

// Extract with password
ExtractionResult result = Rar5j.extract(
    "encrypted.rar",
    "output_directory",
    "mypassword"
);

// Check results
System.out.println("Extracted: " + result.successCount + "/" + result.totalFiles);
if (result.errorCount > 0) {
    result.print();  // Print error details
}
```

### Read archive contents

```java
import be.stef.rar5.Rar5Reader;
import be.stef.rar5.blocks.Rar5FileBlock;

Rar5Reader reader = new Rar5Reader();
reader.read(new File("archive.rar"));

for (Rar5FileBlock file : reader.getFileBlocks()) {
    System.out.println(file.getFileName());
    System.out.println("  Size: " + file.getUnpackedSize());
    System.out.println("  Compressed: " + file.getDataSize());
    System.out.println("  Encrypted: " + file.isEncrypted());
}
```

## Supported Features

| Feature | Status |
|---------|--------|
| Store (no compression) | ✅ |
| LZ compression | ✅ |
| AES-256 encryption | ✅ |
| Encrypted headers | ✅ |
| Encrypted file names | ✅ |
| DELTA filter | ✅ |
| E8/E8E9 filter (x86) | ✅ |
| ARM filter | ✅ |
| Solid archives | ✅ |
| CRC32 verification | ✅ |
| Multi-volume archives | ⚠️ Partial |
| Recovery records | ❌ |
| BLAKE2 hash verification | ❌ |
| RAR4 format | ❌ |

## Project Structure

```
be.stef.rar5
├── Rar5j               # Main class & extraction API
├── Rar5Reader          # Archive structure parser
├── Rar5Constants       # Format constants
├── ExtractionResult    # Extraction results
│
├── blocks/             # Block type parsers
│   ├── Rar5Block
│   ├── Rar5FileBlock
│   ├── Rar5MainArchiveBlock
│   ├── Rar5ServiceBlock
│   ├── Rar5EncryptionBlock
│   └── Rar5EndBlock
│
├── crypto/             # Encryption handling
│   └── Rar5Crypto
│
├── decompress/         # Decompression engine
│   ├── Rar5LZDecoder
│   ├── Rar5HuffmanDecoder
│   ├── Rar5BitDecoder
│   └── Rar5Filter
│
├── extra/              # Extra record parsers
│   ├── Rar5ExtraCrypto
│   ├── Rar5ExtraHash
│   ├── Rar5ExtraTime
│   ├── Rar5ExtraLink
│   └── Rar5ExtraVersion
│
└── util/               # Utilities
    ├── VInt
    ├── VIntReader
    └── SafePathBuilder
```

## Building

```bash
# Compile
javac -d bin src/be/stef/rar5/*.java src/be/stef/rar5/**/*.java

# Create JAR
jar cfe rar5j.jar be.stef.rar5.Rar5j -C bin .
```

## License

Apache License 2.0 — See [LICENSE](LICENSE)

## Author

**Stéphane BURY**

## Acknowledgments

7-Zip by Igor Pavlov was a valuable reference for troubleshooting some decompression challenges.
