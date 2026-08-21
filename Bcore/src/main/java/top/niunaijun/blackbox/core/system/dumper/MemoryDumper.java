package top.niunaijun.blackbox.core.system.dumper;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import top.niunaijun.blackbox.utils.Slog;

/**
 * Memory region dumper - reads /proc/self/maps to find and dump
 * loaded libraries, DEX files, and memory regions at runtime.
 * This is the core of Zygisk-style dumping from virtual memory.
 */
public class MemoryDumper {

    private static final String TAG = "MemoryDumper";

    /**
     * Parse /proc/self/maps and return all memory-mapped regions
     */
    public static List<MemoryRegion> parseMaps() {
        List<MemoryRegion> regions = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                MemoryRegion region = parseMapLine(line);
                if (region != null) {
                    regions.add(region);
                }
            }
            reader.close();
        } catch (Exception e) {
            Slog.e(TAG, "Failed to parse maps: " + e.getMessage());
        }
        return regions;
    }

    /**
     * Parse a single line from /proc/self/maps
     * Format: addr-addr perms offset dev inode pathname
     */
    private static MemoryRegion parseMapLine(String line) {
        try {
            String[] parts = line.split("\\s+");
            if (parts.length < 5) return null;

            String[] addrs = parts[0].split("-");
            if (addrs.length != 2) return null;

            MemoryRegion region = new MemoryRegion();
            region.startAddr = Long.parseLong(addrs[0], 16);
            region.endAddr = Long.parseLong(addrs[1], 16);
            region.perms = parts[1];
            region.offset = Long.parseLong(parts[2], 16);
            region.dev = parts[3];
            region.inode = Long.parseLong(parts[4]);
            region.path = parts.length > 5 ? parts[5] : "";
            region.size = region.endAddr - region.startAddr;

            return region;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Find all loaded .so libraries from maps
     */
    public static List<MemoryRegion> findLoadedLibraries() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.endsWith(".so") && r.offset == 0) {
                if (!result.stream().anyMatch(x -> x.path.equals(r.path))) {
                    result.add(r);
                }
            }
        }
        return result;
    }

    /**
     * Find all DEX files in memory (mapped from APK or extracted)
     */
    public static List<MemoryRegion> findDexRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.endsWith(".dex") || r.path.contains("dex")) {
                result.add(r);
            }
        }
            }
        }
        return result;
    }

    /**
     * Find all .oat/.odex/.vdex files
     */
    public static List<MemoryRegion> findOatRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.endsWith(".oat") || r.path.endsWith(".odex") || r.path.endsWith(".vdex")) {
                result.add(r);
            }
        }
        return result;
    }

    /**
     * Dump a memory region to file
     */
    public static boolean dumpRegion(MemoryRegion region, File outputFile) {
        try {
            // Read from /proc/self/mem at the region's offset
            java.io.RandomAccessFile mem = new java.io.RandomAccessFile("/proc/self/mem", "r");
            mem.seek(region.startAddr);

            FileOutputStream fos = new FileOutputStream(outputFile);
            byte[] buffer = new byte[(int) Math.min(region.size, 8192)];
            long remaining = region.size;
            int totalRead = 0;

            while (remaining > 0) {
                int toRead = (int) Math.min(buffer.length, remaining);
                int read = mem.read(buffer, 0, toRead);
                if (read <= 0) break;
                fos.write(buffer, 0, read);
                remaining -= read;
                totalRead += read;
            }

            fos.close();
            mem.close();
            Slog.i(TAG, "Dumped region: " + region.path + " -> " + outputFile.getName() + " (" + totalRead + " bytes)");
            return true;
        } catch (Exception e) {
            Slog.w(TAG, "Failed to dump region " + region.path + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Dump all loaded libraries to output directory
     */
    public static int dumpAllLibraries(File outputDir) {
        outputDir.mkdirs();
        List<MemoryRegion> libs = findLoadedLibraries();
        int dumped = 0;
        for (MemoryRegion lib : libs) {
            File out = new File(outputDir, new File(lib.path).getName());
            if (dumpRegion(lib, out)) dumped++;
        }
        Slog.i(TAG, "Dumped " + dumped + "/" + libs.size() + " libraries");
        return dumped;
    }

    /**
     * Dump all DEX regions
     */
    public static int dumpAllDex(File outputDir) {
        outputDir.mkdirs();
        List<MemoryRegion> dexRegions = findDexRegions();
        int dumped = 0;
        for (int i = 0; i < dexRegions.size(); i++) {
            MemoryRegion dex = dexRegions.get(i);
            String name = dex.path.isEmpty() ? "memory_dex_" + i + ".dex" : new File(dex.path).getName();
            File out = new File(outputDir, name);
            if (dumpRegion(dex, out)) dumped++;
        }
        Slog.i(TAG, "Dumped " + dumped + "/" + dexRegions.size() + " DEX regions");
        return dumped;
    }

    /**
     * Find a library by name in memory maps
     */
    public static MemoryRegion findLibrary(String name) {
        for (MemoryRegion r : parseMaps()) {
            if (r.path.contains(name) && r.offset == 0) {
                return r;
            }
        }
        return null;
    }

    /**
     * Generate a full memory map report
     */
    public static String generateMapReport() {
        StringBuilder sb = new StringBuilder();
        List<MemoryRegion> regions = parseMaps();

        sb.append("╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║  /proc/self/maps - Memory Region Analysis                    ║\n");
        sb.append("║  Total regions: ").append(regions.size()).append("\n");
        sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");

        // Group by type
        List<MemoryRegion> soFiles = new ArrayList<>();
        List<MemoryRegion> dexFiles = new ArrayList<>();
        List<MemoryRegion> oatFiles = new ArrayList<>();
        List<MemoryRegion> anon = new ArrayList<>();

        for (MemoryRegion r : regions) {
            if (r.path.endsWith(".so")) soFiles.add(r);
            else if (r.path.endsWith(".dex") || r.path.contains("dex")) dexFiles.add(r);
            else if (r.path.endsWith(".oat") || r.path.endsWith(".odex") || r.path.endsWith(".vdex")) oatFiles.add(r);
            else if (r.path.isEmpty()) anon.add(r);
        }

        sb.append("═══ LOADED .SO LIBRARIES (").append(soFiles.size()).append(" regions) ═══\n");
        for (MemoryRegion r : soFiles) {
            sb.append(String.format("  0x%012x - 0x%012x  %s  %s\n",
                r.startAddr, r.endAddr, r.perms, r.path));
        }

        sb.append("\n═══ DEX FILES (").append(dexFiles.size()).append(" regions) ═══\n");
        for (MemoryRegion r : dexFiles) {
            sb.append(String.format("  0x%012x - 0x%012x  %s  %s\n",
                r.startAddr, r.endAddr, r.perms, r.path));
        }

        sb.append("\n═══ OAT/VDEX FILES (").append(oatFiles.size()).append(" regions) ═══\n");
        for (MemoryRegion r : oatFiles) {
            sb.append(String.format("  0x%012x - 0x%012x  %s  %s\n",
                r.startAddr, r.endAddr, r.perms, r.path));
        }

        sb.append("\n═══ ANONYMOUS MEMORY (").append(anon.size()).append(" regions) ═══\n");
        sb.append("  (Showing only executable regions)\n");
        for (MemoryRegion r : anon) {
            if (r.isExecutable()) {
                sb.append(String.format("  0x%012x - 0x%012x  %s  size: %d\n",
                    r.startAddr, r.endAddr, r.perms, r.size));
            }
        }

        return sb.toString();
    }

    public static class MemoryRegion {
        public long startAddr;
        public long endAddr;
        public String perms;
        public long offset;
        public String dev;
        public long inode;
        public String path;
        public long size;
        public byte[] magic;

        public boolean isReadable() { return perms != null && perms.charAt(0) == 'r'; }
        public boolean isWritable() { return perms != null && perms.charAt(1) == 'w'; }
        public boolean isExecutable() { return perms != null && perms.charAt(2) == 'x'; }

        @Override
        public String toString() {
            return String.format("0x%x-0x%x %s %s", startAddr, endAddr, perms, path);
        }
    }
}
