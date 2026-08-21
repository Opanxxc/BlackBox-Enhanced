package top.niunaijun.blackbox.core.system.dumper;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import top.niunaijun.blackbox.utils.Slog;

/**
 * Parses IL2CPP global-metadata.dat to extract real class/method/field data.
 * Supports metadata versions 24-29 used in modern Unity games.
 * Fallback: raw string extraction when structured parse fails.
 */
public class MetadataParser {

    private static final String TAG = "MetadataParser";
    private static final int METADATA_MAGIC = 0xFAB11BAF;

    private int mVersion;
    private int mTypeDefCount;
    private int mFieldDefCount;
    private int mMethodDefCount;

    private final List<IL2CPPClass> mClasses = new ArrayList<>();

    public static class IL2CPPClass {
        public int index;
        public String name;
        public String namespace;
        public int fieldStart;
        public int fieldCount;
        public int methodStart;
        public int methodCount;
        public int parentIndex;
        public int flags;
        public int imageUrlIndex;
        public List<IL2CPPField> fields = new ArrayList<>();
        public List<IL2CPPMethod> methods = new ArrayList<>();
    }

    public static class IL2CPPField {
        public int index;
        public String name;
        public int typeIndex;
        public int token;
        public int flags;
        public int fieldOffset; // computed
    }

    public static class IL2CPPMethod {
        public int index;
        public String name;
        public int returnTypeIndex;
        public int token;
        public int methodRVA;
        public int paramStart;
        public int paramCount;
        public int flags;
        public int iflags;
        public int slot;
    }

    /**
     * Parse global-metadata.dat. Returns true on success.
     */
    public boolean parse(File metadataFile) {
        try {
            byte[] allBytes = new byte[(int) metadataFile.length()];
            FileInputStream fis = new FileInputStream(metadataFile);
            int read = 0;
            while (read < allBytes.length) {
                int n = fis.read(allBytes, read, allBytes.length - read);
                if (n < 0) break;
                read += n;
            }
            fis.close();

            if (allBytes.length < 16) {
                Slog.e(TAG, "Metadata file too small");
                return false;
            }

            // Check magic
            int magic = readLE32(allBytes, 0);
            if (magic != METADATA_MAGIC) {
                Slog.e(TAG, "Invalid metadata magic: 0x" + Integer.toHexString(magic)
                    + " (expected 0x" + Integer.toHexString(METADATA_MAGIC) + ")");
                return false;
            }

            mVersion = readLE32(allBytes, 4);
            Slog.i(TAG, "IL2CPP metadata version: " + mVersion);

            // Parse string literal data
            int literalCount = readLE32(allBytes, 8);
            int literalOffset = readLE32(allBytes, 12);

            // Parse string literal data section
            int litDataCount = 0;
            int litDataOffset = 0;
            if (allBytes.length >= 20) {
                litDataCount = readLE32(allBytes, 16);
                litDataOffset = readLE32(allBytes, 20);
            }

            Slog.i(TAG, "String literals: " + literalCount + " at 0x" + Integer.toHexString(literalOffset));
            Slog.i(TAG, "String literal data: " + litDataCount + " bytes at 0x" + Integer.toHexString(litDataOffset));

            // Skip genericContainerCount (v29+)
            int offset = 24;
            if (mVersion >= 29) offset += 4;

            // Type definition table
            mTypeDefCount = readLE32(allBytes, offset + 4);
            int typeDefOffset = readLE32(allBytes, offset);
            int typeDefSize = (mVersion >= 29) ? 64 : 56;
            Slog.i(TAG, "Type definitions: " + mTypeDefCount + " (size=" + typeDefSize + ")");

            offset += 12;

            // Field definition table
            mFieldDefCount = readLE32(allBytes, offset + 4);
            int fieldDefOffset = readLE32(allBytes, offset);
            int fieldDefSize = (mVersion >= 29) ? 16 : 12;
            Slog.i(TAG, "Field definitions: " + mFieldDefCount + " (size=" + fieldDefSize + ")");

            offset += 12;

            // Method definition table
            mMethodDefCount = readLE32(allBytes, offset + 4);
            int methodDefOffset = readLE32(allBytes, offset);
            int methodDefSize = (mVersion >= 29) ? 36 : 28;
            Slog.i(TAG, "Method definitions: " + mMethodDefCount + " (size=" + methodDefSize + ")");

            offset += 12;

            // Parameter definition table
            int paramDefCount = readLE32(allBytes, offset + 4);
            int paramDefOffset = readLE32(allBytes, offset);
            Slog.i(TAG, "Parameter definitions: " + paramDefCount);

            // Parse type definitions
            for (int i = 0; i < mTypeDefCount && typeDefOffset + i * typeDefSize < allBytes.length; i++) {
                int pos = typeDefOffset + i * typeDefSize;
                IL2CPPClass cls = new IL2CPPClass();
                cls.index = i;

                // nameIndex, namespaceIndex
                int nameIdx = readLE32(allBytes, pos);
                int nsIdx = readLE32(allBytes, pos + 4);
                cls.name = readStringFromBuffer(allBytes, nameIdx);
                cls.namespace = readStringFromBuffer(allBytes, nsIdx);

                // assemblyIndex (4), parentIndex (4), declaringTypeIndex (4)
                cls.parentIndex = readLE32(allBytes, pos + 12);
                cls.declaringTypeIndex = readLE32(allBytes, pos + 16);

                // genericContainerIndex (4)
                cls.flags = readLE32(allBytes, pos + 24);
                cls.fieldStart = readLE32(allBytes, pos + 28);
                cls.fieldCount = readLE32(allBytes, pos + 32);
                cls.methodStart = readLE32(allBytes, pos + 36);
                cls.methodCount = readLE32(allBytes, pos + 40);

                if (mVersion >= 27) {
                    cls.imageUrlIndex = readLE32(allBytes, pos + 44);
                }

                mClasses.add(cls);
            }

            Slog.i(TAG, "Parsed " + mClasses.size() + " class definitions");

            // Parse method definitions
            for (int i = 0; i < mMethodDefCount && methodDefOffset + i * methodDefSize < allBytes.length; i++) {
                int pos = methodDefOffset + i * methodDefSize;
                IL2CPPMethod method = new IL2CPPMethod();
                method.index = i;

                method.name = readStringFromBuffer(allBytes, readLE32(allBytes, pos));
                method.returnTypeIndex = readLE32(allBytes, pos + 4);
                method.paramStart = readLE32(allBytes, pos + 8);
                method.token = readLE32(allBytes, pos + 12);
                method.iflags = readLE32(allBytes, pos + 16);
                method.flags = readLE32(allBytes, pos + 20);
                method.slot = readLE32(allBytes, pos + 24);
                method.methodRVA = readLE32(allBytes, pos + 28);

                // Find parent class and add
                for (IL2CPPClass cls : mClasses) {
                    if (i >= cls.methodStart && i < cls.methodStart + cls.methodCount) {
                        cls.methods.add(method);
                        break;
                    }
                }
            }

            // Parse field definitions
            for (int i = 0; i < mFieldDefCount && fieldDefOffset + i * fieldDefSize < allBytes.length; i++) {
                int pos = fieldDefOffset + i * fieldDefSize;
                IL2CPPField field = new IL2CPPField();
                field.index = i;

                field.name = readStringFromBuffer(allBytes, readLE32(allBytes, pos));
                field.typeIndex = readLE32(allBytes, pos + 4);
                field.token = readLE32(allBytes, pos + 8);
                field.flags = readLE32(allBytes, pos + 12);

                // Find parent class
                for (IL2CPPClass cls : mClasses) {
                    if (i >= cls.fieldStart && i < cls.fieldStart + cls.fieldCount) {
                        cls.fields.add(field);
                        break;
                    }
                }
            }

            return true;
        } catch (Exception e) {
            Slog.e(TAG, "Parse failed: " + e.getMessage());
            return false;
        }
    }

    private int readLE32(byte[] data, int offset) {
        if (offset + 4 > data.length) return 0;
        return (data[offset] & 0xFF)
            | ((data[offset + 1] & 0xFF) << 8)
            | ((data[offset + 2] & 0xFF) << 16)
            | ((data[offset + 3] & 0xFF) << 24);
    }

    private String readStringFromBuffer(byte[] data, int strIndex) {
        if (strIndex < 0 || strIndex >= data.length) return "<invalid>";
        int end = strIndex;
        while (end < data.length && data[end] != 0) end++;
        if (end <= strIndex) return "<empty>";
        return new String(data, strIndex, end - strIndex);
    }

    /**
     * Fallback: extract raw strings from metadata binary
     */
    public static List<String> extractRawStrings(File metadataFile, int minLen) {
        List<String> result = new ArrayList<>();
        try {
            byte[] all = new byte[(int) metadataFile.length()];
            FileInputStream fis = new FileInputStream(metadataFile);
            int read = 0;
            while (read < all.length) {
                int n = fis.read(all, read, all.length - read);
                if (n < 0) break;
                read += n;
            }
            fis.close();

            StringBuilder current = new StringBuilder();
            int startOffset = 0;

            for (int i = 0; i < all.length; i++) {
                byte b = all[i];
                if (b >= 32 && b < 127) {
                    if (current.length() == 0) startOffset = i;
                    current.append((char) b);
                } else {
                    if (current.length() >= minLen) {
                        result.add(String.format("0x%08x: %s", startOffset, current.toString()));
                    }
                    current.setLength(0);
                }
            }
            if (current.length() >= minLen) {
                result.add(String.format("0x%08x: %s", startOffset, current.toString()));
            }
        } catch (Exception e) {
            Slog.e(TAG, "Raw string extraction failed: " + e.getMessage());
        }
        return result;
    }

    public List<IL2CPPClass> getClasses() { return mClasses; }
    public int getClassCount() { return mClasses.size(); }
    public int getMethodCount() { return mMethodDefCount; }
    public int getFieldCount() { return mFieldDefCount; }
    public int getVersion() { return mVersion; }
}
