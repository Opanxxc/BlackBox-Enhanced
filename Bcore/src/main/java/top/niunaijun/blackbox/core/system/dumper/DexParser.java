package top.niunaijun.blackbox.core.system.dumper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Real DEX file parser - extracts actual class names, method names,
 * field names, string pool, and type descriptors from DEX binary.
 * DEX format: https://source.android.com/docs/core/runtime/dex-format
 */
public class DexParser {

    private static final int DEX_MAGIC = 0x0A786564; // "\ndeX\0"
    private static final int DEX_MAGIC_LE = 0x6465780A;

    private ByteBuffer mBuffer;
    private int mHeaderSize;
    private int mStringIdsSize;
    private int mStringIdsOff;
    private int mTypeIdsSize;
    private int mTypeIdsOff;
    private int mProtoIdsSize;
    private int mProtoIdsOff;
    private int mMethodIdsSize;
    private int mMethodIdsOff;
    private int mFieldIdsSize;
    private int mFieldIdsOff;
    private int mClassDefsSize;
    private int mClassDefsOff;
    private int mMapOff;

    private String[] mStrings;
    private String[] mTypes;

    public static class DexClass {
        public int classIdx;
        public String className;
        public String superclass;
        public String sourceFile;
        public int accessFlags;
        public int classDataOff;
        public List<DexMethod> methods = new ArrayList<>();
        public List<DexField> fields = new ArrayList<>();
    }

    public static class DexMethod {
        public int methodIdx;
        public String className;
        public String methodName;
        public String returnType;
        public String parameterTypes;
        public int accessFlags;
        public int codeOff;
    }

    public static class DexField {
        public int fieldIdx;
        public String className;
        public String fieldName;
        public String type;
        public int accessFlags;
    }

    public static class DexString {
        public int offset;
        public String value;
    }

    /**
     * Parse a DEX file
     */
    public boolean parse(File dexFile) {
        try {
            mBuffer = ByteBuffer.allocate((int) dexFile.length());
            FileInputStream fis = new FileInputStream(dexFile);
            fis.read(mBuffer.array());
            fis.close();
            mBuffer.order(ByteOrder.LITTLE_ENDIAN);
            mBuffer.position(0);

            // Read header
            int magic = mBuffer.getInt();
            if (magic != DEX_MAGIC && magic != DEX_MAGIC_LE) {
                return false;
            }

            mBuffer.getInt(); // checksum
            byte[] sig = new byte[20];
            mBuffer.get(sig);
            mBuffer.getInt(); // file size
            mHeaderSize = mBuffer.getInt();
            mBuffer.getInt(); // endian tag

            int linkSize = mBuffer.getInt();
            int linkOff = mBuffer.getInt();
            mMapOff = mBuffer.getInt();
            mStringIdsSize = mBuffer.getInt();
            mStringIdsOff = mBuffer.getInt();
            mTypeIdsSize = mBuffer.getInt();
            mTypeIdsOff = mBuffer.getInt();
            mProtoIdsSize = mBuffer.getInt();
            mProtoIdsOff = mBuffer.getInt();
            mFieldIdsSize = mBuffer.getInt();
            mFieldIdsOff = mBuffer.getInt();
            mMethodIdsSize = mBuffer.getInt();
            mMethodIdsOff = mBuffer.getInt();
            mClassDefsSize = mBuffer.getInt();
            mClassDefsOff = mBuffer.getInt();
            mBuffer.getInt(); // data_size
            mBuffer.getInt(); // data_off

            // Read string pool
            readStrings();
            // Read type pool
            readTypes();

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void readStrings() {
        mStrings = new String[mStringIdsSize];
        for (int i = 0; i < mStringIdsSize; i++) {
            mBuffer.position(mStringIdsOff + i * 4);
            int strOff = mBuffer.getInt();
            mStrings[i] = readString(strOff);
        }
    }

    private String readString(int offset) {
        try {
            mBuffer.position(offset);
            int utf16Size = readULEB128();
            int bytes = readULEB128();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes; i++) {
                byte b = mBuffer.get();
                if (b == 0) break;
                sb.append((char) (b & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return "<invalid>";
        }
    }

    private int readULEB128() {
        int result = 0;
        int shift = 0;
        byte b;
        do {
            b = mBuffer.get();
            result |= (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    private void readTypes() {
        mTypes = new String[mTypeIdsSize];
        for (int i = 0; i < mTypeIdsSize; i++) {
            mBuffer.position(mTypeIdsOff + i * 4);
            int descriptorIdx = mBuffer.getInt();
            mTypes[i] = descriptorIdx < mStrings.length ? mStrings[descriptorIdx] : "?";
        }
    }

    /**
     * Extract all class names
     */
    public List<String> getClassNames() {
        List<String> classes = new ArrayList<>();
        for (int i = 0; i < mClassDefsSize; i++) {
            mBuffer.position(mClassDefsOff + i * 32);
            int classIdx = mBuffer.getInt();
            mBuffer.getInt(); // access_flags
            mBuffer.getInt(); // superclass_idx
            mBuffer.getInt(); // interfaces_off
            mBuffer.getInt(); // source_file_idx
            mBuffer.getInt(); // annotations_off
            int classDataOff = mBuffer.getInt();
            mBuffer.getInt(); // static_values_off

            String name = classIdx < mTypes.length ? mTypes[classIdx] : "class_" + i;
            classes.add(name.replace("/", ".").replace(";", ""));
        }
        return classes;
    }

    /**
     * Parse all classes with methods and fields
     */
    public List<DexClass> parseClasses() {
        List<DexClass> classes = new ArrayList<>();
        for (int i = 0; i < mClassDefsSize; i++) {
            mBuffer.position(mClassDefsOff + i * 32);
            int classIdx = mBuffer.getInt();
            int accessFlags = mBuffer.getInt();
            int superclassIdx = mBuffer.getInt();
            mBuffer.getInt(); // interfaces_off
            int sourceFileIdx = mBuffer.getInt();
            mBuffer.getInt(); // annotations_off
            int classDataOff = mBuffer.getInt();
            mBuffer.getInt(); // static_values_off

            DexClass cls = new DexClass();
            cls.classIdx = classIdx;
            cls.className = classIdx < mTypes.length ? mTypes[classIdx] : "class_" + i;
            cls.className = cls.className.replace("/", ".").replace(";", "");
            cls.superclass = superclassIdx >= 0 && superclassIdx < mTypes.length
                ? mTypes[superclassIdx].replace("/", ".").replace(";", "") : "";
            cls.sourceFile = sourceFileIdx >= 0 && sourceFileIdx < mStrings.length
                ? mStrings[sourceFileIdx] : "";
            cls.accessFlags = accessFlags;
            cls.classDataOff = classDataOff;

            // Parse class_data_item
            if (classDataOff > 0) {
                parseClassData(cls, classDataOff);
            }

            classes.add(cls);
        }
        return classes;
    }

    private void parseClassData(DexClass cls, int offset) {
        try {
            mBuffer.position(offset);
            int staticFieldsSize = readULEB128();
            int instanceFieldsSize = readULEB128();
            int directMethodsSize = readULEB128();
            int virtualMethodsSize = readULEB128();

            int fieldIdx = 0;
            for (int i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
                fieldIdx += readULEB128();
                int accessFlags = readULEB128();
                DexField field = new DexField();
                field.fieldIdx = fieldIdx;
                field.accessFlags = accessFlags;
                if (fieldIdx < mFieldIdsSize) {
                    mBuffer.position(mFieldIdsOff + fieldIdx * 8);
                    int classIdx = mBuffer.getInt();
                    int typeIdx = mBuffer.getInt();
                    int nameIdx = mBuffer.getInt();
                    field.className = classIdx < mTypes.length ? simplifyType(mTypes[classIdx]) : "?";
                    field.fieldName = nameIdx < mStrings.length ? mStrings[nameIdx] : "?";
                    field.type = typeIdx < mTypes.length ? simplifyType(mTypes[typeIdx]) : "?";
                }
                cls.fields.add(field);
            }

            int methodIdx = 0;
            for (int i = 0; i < directMethodsSize + virtualMethodsSize; i++) {
                methodIdx += readULEB128();
                int accessFlags = readULEB128();
                int codeOff = readULEB128();
                DexMethod method = new DexMethod();
                method.methodIdx = methodIdx;
                method.accessFlags = accessFlags;
                method.codeOff = codeOff;
                if (methodIdx < mMethodIdsSize) {
                    mBuffer.position(mMethodIdsOff + methodIdx * 8);
                    int classIdx = mBuffer.getInt();
                    int protoIdx = mBuffer.getInt();
                    int nameIdx = mBuffer.getInt();
                    method.className = classIdx < mTypes.length ? simplifyType(mTypes[classIdx]) : "?";
                    method.methodName = nameIdx < mStrings.length ? mStrings[nameIdx] : "?";
                    // Resolve return type from proto
                    if (protoIdx < mProtoIdsSize) {
                        mBuffer.position(mProtoIdsOff + protoIdx * 12);
                        int retTypeIdx = mBuffer.getInt();
                        method.returnType = retTypeIdx < mTypes.length ? simplifyType(mTypes[retTypeIdx]) : "?";
                    }
                    method.className = cls.className;
                }
                cls.methods.add(method);
            }
        } catch (Exception e) {
            // partial parse
        }
    }

    private String simplifyType(String type) {
        if (type == null) return "?";
        // "Ljava/lang/String;" -> "String"
        // "[I" -> "int[]"
        // "Ljava/lang/Object;" -> "Object"
        String t = type.replace("/", ".");
        if (t.startsWith("L") && t.endsWith(";")) {
            t = t.substring(1, t.length() - 1);
        }
        return t;
    }

    /**
     * Extract all strings from the DEX string pool with offsets
     */
    public List<DexString> extractStrings() {
        List<DexString> result = new ArrayList<>();
        for (int i = 0; i < mStringIdsSize; i++) {
            mBuffer.position(mStringIdsOff + i * 4);
            int strOff = mBuffer.getInt();
            String value = readString(strOff);
            DexString ds = new DexString();
            ds.offset = strOff;
            ds.value = value;
            result.add(ds);
        }
        return result;
    }

    /**
     * Get raw bytes for hexdump
     */
    public byte[] getBytes() {
        return mBuffer.array();
    }

    public int getStringCount() { return mStringIdsSize; }
    public int getTypeCount() { return mTypeIdsSize; }
    public int getMethodCount() { return mMethodIdsSize; }
    public int getFieldCount() { return mFieldIdsSize; }
    public int getClassCount() { return mClassDefsSize; }
}
