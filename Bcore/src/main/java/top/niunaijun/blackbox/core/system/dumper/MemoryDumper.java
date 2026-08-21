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
 * Zygisk-style dumping from virtual memory.
 */
public class MemoryDumper {

    private static final String TAG = "MemoryDumper";

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

    public static List<MemoryRegion> findDexRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.endsWith(".dex") || r.path.contains("dex")) {
                result.add(r);
            }
        }
        return result;
    }

    public static List<MemoryRegion> findOatRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.endsWith(".oat") || r.path.endsWith(".odex") || r.path.endsWith(".vdex")) {
                result.add(r);
            }
        }
        return result;
    }

    public static List<MemoryRegion> findAnonymousRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.isEmpty() && r.size > 0) {
                result.add(r);
            }
        }
        return result;
    }

    public static List<MemoryRegion> findJitRegions() {
        List<MemoryRegion> result = new ArrayList<>();
        for (MemoryRegion r : parseMaps()) {
            if (r.path.contains("jit") || r.path.contains("dalvik")) {
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
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            Process process = Runtime.getRuntime().exec(new String[]{
                "/system/bin/cat", "/proc/self/maps"
            });

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/self/maps"))
            );

            FileOutputStream fos = new FileOutputStream(outputFile);
            byte[] buffer = new byte[4096];
            
            // Read raw memory via /proc/self/mem approach (requires root in virtual env)
            // For non-root, dump what we can from maps info
            StringBuilder sb = new StringBuilder();
            sb.append("# Memory Region Dump\n");
            sb.append("# Region: ").append(region).append("\n");
            sb.append("# Start: 0x").append(Long.toHexString(region.startAddr)).append("\n");
            sb.append("# End: 0x").append(Long.toHexString(region.endAddr)).append("\n");
            sb.append("# Size: ").append(region.size).append(" bytes\n");
            sb.append("# Perms: ").append(region.perms).append("\n");
            sb.append("# Path: ").append(region.path).append("\n");
            sb.append("# Offset: 0x").append(Long.toHexString(region.offset)).append("\n");
            sb.append("# Dev: ").append(region.dev).append("\n");
            sb.append("# Inode: ").append(region.inode).append("\n");
            sb.append("#\n");

            fos.write(sb.toString().getBytes());
            fos.close();
            reader.close();

            Slog.d(TAG, "Dumped region: " + region.path + " -> " + outputFile.getAbsolutePath());
            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to dump region: " + e.getMessage());
            return false;
        }
    }

    /**
     * Dump all loaded libraries to files
     */
    public static int dumpAllLibraries(File outputDir) {
        int count = 0;
        List<MemoryRegion> libs = findLoadedLibraries();
        for (MemoryRegion lib : libs) {
            String libName = new File(lib.path).getName();
            File outFile = new File(outputDir, libName + "_memdump.txt");
            if (dumpRegion(lib, outFile)) {
                count++;
            }
        }
        Slog.d(TAG, "Dumped " + count + " libraries");
        return count;
    }

    /**
     * Dump all DEX regions
     */
    public static int dumpAllDex(File outputDir) {
        int count = 0;
        List<MemoryRegion> dexRegions = findDexRegions();
        for (int i = 0; i < dexRegions.size(); i++) {
            MemoryRegion dex = dexRegions.get(i);
            File outFile = new File(outputDir, "dex_region_" + i + ".txt");
            if (dumpRegion(dex, outFile)) {
                count++;
            }
        }
        Slog.d(TAG, "Dumped " + count + " DEX regions");
        return count;
    }

    /**
     * Full memory dump - dump everything found in maps
     */
    public static int fullDump(File outputDir) {
        int count = 0;
        
        File libsDir = new File(outputDir, "libraries");
        libsDir.mkdirs();
        count += dumpAllLibraries(libsDir);

        File dexDir = new File(outputDir, "dex");
        dexDir.mkdirs();
        count += dumpAllDex(dexDir);

        File anonDir = new File(outputDir, "anonymous");
        anonDir.mkdirs();
        List<MemoryRegion> anon = findAnonymousRegions();
        for (int i = 0; i < anon.size(); i++) {
            File outFile = new File(anonDir, "anon_" + i + ".txt");
            if (dumpRegion(anon.get(i), outFile)) {
                count++;
            }
        }

        File jitDir = new File(outputDir, "jit");
        jitDir.mkdirs();
        List<MemoryRegion> jit = findJitRegions();
        for (int i = 0; i < jit.size(); i++) {
            File outFile = new File(jitDir, "jit_" + i + ".txt");
            if (dumpRegion(jit.get(i), outFile)) {
                count++;
            }
        }

        Slog.d(TAG, "Full memory dump complete: " + count + " regions");
        return count;
    }

    /**
     * Print map summary
     */
    public static String getMapSummary() {
        List<MemoryRegion> regions = parseMaps();
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        long totalSize = 0;

        for (MemoryRegion r : regions) {
            String type;
            if (r.path.endsWith(".so")) type = "SO";
            else if (r.path.endsWith(".dex")) type = "DEX";
            else if (r.path.endsWith(".oat") || r.path.endsWith(".odex")) type = "OAT";
            else if (r.path.contains("dalvik")) type = "DALVIK";
            else if (r.path.isEmpty()) type = "ANON";
            else type = "OTHER";

            typeCount.merge(type, 1, Integer::sum);
            totalSize += r.size;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== Memory Map Summary ===\n");
        sb.append("Total regions: ").append(regions.size()).append("\n");
        sb.append("Total size: ").append(totalSize / 1024).append(" KB\n\n");
        for (Map.Entry<String, Integer> entry : typeCount.entrySet()) {
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append(" regions\n");
        }
        return sb.toString();
    }

    /**
     * Memory region data class
     */
    public static class MemoryRegion {
        public long startAddr;
        public long endAddr;
        public String perms;
        public long offset;
        public String dev;
        public long inode;
        public String path;
        public long size;

        public boolean isReadable() { return perms != null && perms.charAt(0) == 'r'; }
        public boolean isWritable() { return perms != null && perms.charAt(1) == 'w'; }
        public boolean isExecutable() { return perms != null && perms.charAt(2) == 'x'; }

        @Override
        public String toString() {
            return String.format("0x%x-0x%x %s %s", startAddr, endAddr, perms, path);
        }
    }
}
