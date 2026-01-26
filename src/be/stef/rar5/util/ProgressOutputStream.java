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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream qui affiche la progression sur la même ligne.
 */
public class ProgressOutputStream extends FilterOutputStream {
    private final long totalSize;
    private final String fileName;
    private long bytesWritten = 0;
    private int lastPercent = -1;
    
    public ProgressOutputStream(OutputStream out, long totalSize, String fileName) {
        super(out);
        this.totalSize = totalSize;
        this.fileName = fileName;
    }
    
    @Override
    public void write(int b) throws IOException {
        out.write(b);
        bytesWritten++;
        updateProgress();
    }
    
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        bytesWritten += len;
        updateProgress();
    }
    
    private void updateProgress() {
        if (totalSize <= 0) return;
        
        int percent = (int) ((bytesWritten * 100) / totalSize);
        
        // N'affiche que si le pourcentage change
        if (percent != lastPercent) {
            lastPercent = percent;
            printProgress(percent);
        }
    }
    
    private void printProgress(int percent) {
        // Barre de progression visuelle
        int barWidth = 30;
        int filled = (percent * barWidth) / 100;
        
        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barWidth; i++) {
            bar.append(i < filled ? "=" : " ");
        }
        bar.append("]");
        
        // \r revient au début de la ligne
        System.out.printf("\r%s %s %3d%% (%s)", bar, formatSize(bytesWritten), percent, truncateFileName(fileName, 30));
    }
    
    /**
     * Appelé à la fin pour passer à la ligne suivante.
     */
    public void finish() {
        System.out.println(); // Nouvelle ligne après complétion
    }
    
    private static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f Ko", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f Mo", bytes / (1024.0 * 1024));
        return String.format("%.2f Go", bytes / (1024.0 * 1024 * 1024));
    }
    
    private static String truncateFileName(String name, int maxLen) {
        if (name.length() <= maxLen) return name;
        return "..." + name.substring(name.length() - maxLen + 3);
    }
}
