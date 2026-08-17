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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream that displays progress on a single line.
 *
 * <p>When extraction completes, {@link #finish()} reprints the line with the
 * elapsed time appended, for example:</p>
 * <pre>
 * [==============================] 4,2 MB 100% (setup.exe) -&gt; 5 sec
 * [==============================] 1,8 GB 100% (image.iso) -&gt; 3 min 24 sec
 * </pre>
 */
public class ProgressOutputStream extends FilterOutputStream {
    private final long totalSize;
    private final String fileName;
    private final long startTime;
    private long bytesWritten = 0;
    private int lastPercent = -1;
    
    public ProgressOutputStream(OutputStream out, long totalSize, String fileName) {
        super(out);
        this.totalSize = totalSize;
        this.fileName = fileName;
        this.startTime = System.nanoTime();
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
        
        // Print only when the percentage changes
        if (percent != lastPercent) {
            lastPercent = percent;
            printProgress(percent, null);
        }
    }
    
    /**
     * Prints the progress line.
     *
     * @param percent  completion percentage
     * @param duration formatted elapsed time to append, or null while running
     */
    private void printProgress(int percent, String duration) {
        // Visual progress bar
        int barWidth = 30;
        int filled = (percent * barWidth) / 100;
        
        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barWidth; i++) {
            bar.append(i < filled ? "=" : " ");
        }
        bar.append("]");
        
        // \r returns to the beginning of the line
        System.out.printf("\r%s %s %3d%% (%s)", bar, formatSize(bytesWritten), percent, truncateFileName(fileName, 30));
        if (duration != null) {
            System.out.print(" -> " + duration);
        }
    }
    
    /**
     * Called at the end to append the elapsed time and move to the next line.
     */
    public void finish() {
        if (totalSize > 0) {
            printProgress(lastPercent < 0 ? 0 : lastPercent, formatDuration(getElapsedMillis()));
        }
        System.out.println(); // New line after completion
    }
    
    /**
     * Returns the time elapsed since this stream was created.
     *
     * @return elapsed time in milliseconds
     */
    public long getElapsedMillis() {
        return (System.nanoTime() - startTime) / 1_000_000L;
    }
    
    /**
     * Formats a duration as "5 sec", "3 min 24 sec" or "1 h 5 min 3 sec".
     *
     * @param millis duration in milliseconds
     * @return human-readable duration
     */
    public static String formatDuration(long millis) {
        if (millis < 1000) return millis + " ms";
        
        long totalSec = millis / 1000;
        long hours    = totalSec / 3600;
        long minutes  = (totalSec % 3600) / 60;
        long seconds  = totalSec % 60;
        
        if (hours > 0)   return hours + " h " + minutes + " min " + seconds + " sec";
        if (minutes > 0) return minutes + " min " + seconds + " sec";
        return seconds + " sec";
    }
    
    private static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
    
    private static String truncateFileName(String name, int maxLen) {
        if (name.length() <= maxLen) return name;
        return "..." + name.substring(name.length() - maxLen + 3);
    }
}