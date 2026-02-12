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
package be.stef.rar5.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class SafePathBuilder {
    private static final Pattern ILLEGAL_CHARS = Pattern.compile("[<>:\"|?*\\u0000-\\u001F]");
    private final Set<String> writtenPaths = new HashSet<>();
    private final File baseDir;
    private final boolean isCaseSensitiveFS;
    
    private static final List<String> RESERVED_NAMES = Arrays.asList(
       "CON", "PRN", "AUX", "NUL", 
       "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
       "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    );


    public SafePathBuilder(File outputDirectory) { //throws IOException {
        this.baseDir = outputDirectory;
        if (!baseDir.exists()) baseDir.mkdirs();
        
        // --- DÉTECTION PHYSIQUE DU SYSTÈME DE FICHIERS ---
        this.isCaseSensitiveFS = detectCaseSensitivity(outputDirectory);
//        System.out.println("  [FS INFO] Case-Sensitive FS: " + this.isCaseSensitiveFS);
    }

    /**
     * Teste réellement si le disque cible est sensible à la casse.
     */
    private boolean detectCaseSensitivity(File dir) {
        try {
            Path testFile = Files.createTempFile(dir.toPath(), ".case_test_", ".tmp");
            boolean sensitive = !Files.exists(Paths.get(testFile.toString().toUpperCase()));
            Files.delete(testFile);
            return sensitive;
        } catch (IOException e) {
            // Repli sur une détection par OS si le test échoue
            String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
            return !(os.contains("win") || os.contains("mac"));
        }
    }

    public File buildSafePath(String originalPath) throws IOException {
        // Normalisation et sécurisation du chemin
        String normalized = originalPath.replace("\\", "/"); 
        Path p = Paths.get(normalized);
        Path safePath = Paths.get("");

        for (Path component : p) {
            String sanitizedName = sanitizeComponent(component.toString());
            safePath = safePath.resolve(sanitizedName);
        }

        File destFile = new File(baseDir, safePath.toString());
        
        // Protection Path Traversal
        if (!destFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new IOException("Security Error: Path traversal attempt: " + originalPath);
        }

        return resolveCollision(destFile);
    }

    /**
     * Builds a safe directory path with sanitization and path traversal protection,
     * but WITHOUT collision detection. Directories that already exist are normal
     * (created by mkdirs() during file extraction) and should not be renamed.
     */
    public File buildSafeDirPath(String originalPath) throws IOException {
        String normalized = originalPath.replace("\\", "/"); 
        Path p = Paths.get(normalized);
        Path safePath = Paths.get("");

        for (Path component : p) {
            String sanitizedName = sanitizeComponent(component.toString());
            safePath = safePath.resolve(sanitizedName);
        }

        File destFile = new File(baseDir, safePath.toString());
        
        // Protection Path Traversal
        if (!destFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
            throw new IOException("Security Error: Path traversal attempt: " + originalPath);

        }

        return destFile;
    }

    private String sanitizeComponent(String name) {
        // 1. Caractères interdits
        String clean = ILLEGAL_CHARS.matcher(name).replaceAll("_");
        
        // 2. Nettoyage points/espaces finaux (critique pour Windows)
        clean = clean.trim();
        while (clean.endsWith(".")) {
            clean = clean.substring(0, clean.length() - 1) + "_";
        }
        
        if (clean.isEmpty()) clean = "_empty_";

        // 3. Gestion des RESERVED_NAMES (ex: AUX.txt -> _AUX_.txt)
        String nameNoExt = clean.contains(".") ? clean.substring(0, clean.lastIndexOf('.')) : clean;
        if (RESERVED_NAMES.contains(nameNoExt.toUpperCase(Locale.ROOT))) {
            clean = "_" + clean + "_";
        }
        
        return clean;
    }

    private File resolveCollision(File file) {
        File finalFile = file;
        String parent = file.getParent();
        String name = file.getName();
        
        String baseName = name;
        String extension = "";
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex > 0) {
            baseName = name.substring(0, dotIndex);
            extension = name.substring(dotIndex);
        }

        int counter = 1;
        String checkKey = getCollisionKey(finalFile);

        // La boucle tourne tant qu'on a une collision "logique" (notre session) 
        // ou "physique" (le fichier est déjà sur le disque)
        while (writtenPaths.contains(checkKey) || finalFile.exists()) {
            String newName = baseName + "_" + counter + extension;
            finalFile = new File(parent, newName);
            checkKey = getCollisionKey(finalFile);
            counter++;
        }

        writtenPaths.add(checkKey);
        return finalFile;
    }

    private String getCollisionKey(File f) {
        String path = f.getAbsolutePath();
        return isCaseSensitiveFS ? path : path.toLowerCase(Locale.ROOT);
    }
}

