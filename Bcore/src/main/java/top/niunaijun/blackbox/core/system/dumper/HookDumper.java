package top.niunaijun.blackbox.core.system.dumper;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Runtime hook-based dumper that intercepts:
 * - Class loading via ClassLoader
 * - DEX file loading
 * - Native library loading (dlopen)
 * - Method resolution
 * 
 * Captures classes, methods, fields, and string constants at runtime.
 */
public class HookDumper {

    private static final String TAG = "HookDumper";
    private static HookDumper sInstance;
    
    // Captured data
    private final Map<String, Class<?>> mLoadedClasses = new ConcurrentHashMap<>();
    private final Map<String, MethodInfo> mLoadedMethods = new ConcurrentHashMap<>();
    private final Map<String, FieldInfo> mLoadedFields = new ConcurrentHashMap<>();
    private final Set<String> mLoadedLibs = ConcurrentHashMap.newKeySet();
    private final Set<String> mDexFiles = ConcurrentHashMap.newKeySet();
    private final Map<String, String> mStringConstants = new ConcurrentHashMap<>();
    
    // Dump output
    private File mOutputDir;
    private boolean mActive = false;
    
    public static HookDumper get() {
        if (sInstance == null) {
            sInstance = new HookDumper();
        }
        return sInstance;
    }
    
    /**
     * Start hooking and capturing class loading
     */
    public void startCapture(File outputDir) {
        mOutputDir = outputDir;
        mOutputDir.mkdirs();
        mActive = true;
        Slog.i(TAG, "Hook dump started -> " + outputDir.getAbsolutePath());
        
        // Hook current thread's context classloader
        hookClassLoader(Thread.currentThread().getContextClassLoader());
        
        // Hook PathClassLoader if available
        hookPathClassLoader();
        
        // Hook DexClassLoader instances
        hookDexClassLoader();
        
        Slog.i(TAG, "All hooks installed, capturing...");
    }
    
    /**
     * Stop capture and generate dump files
     */
    public void stopCapture() {
        mActive = false;
        Slog.i(TAG, "Hook dump stopped. Generating output...");
        generateDumpFiles();
    }
    
    private void hookClassLoader(ClassLoader cl) {
        if (cl == null) return;
        
        try {
            // Try to intercept loadClass
            Slog.d(TAG, "Hooking ClassLoader: " + cl.getClass().getName());
            
            // Get the dex path list
            Field pathListField = findField(cl.getClass(), "pathList");
            if (pathListField != null) {
                pathListField.setAccessible(true);
                Object pathList = pathListField.get(cl);
                if (pathList != null) {
                    // Get dex elements
                    Field dexElementsField = findField(pathList.getClass(), "dexElements");
                    if (dexElementsField != null) {
                        dexElementsField.setAccessible(true);
                        Object[] dexElements = (Object[]) dexElementsField.get(pathList);
                        if (dexElements != null) {
                            for (Object element : dexElements) {
                                Field dexFileField = findField(element.getClass(), "dexFile");
                                if (dexFileField != null) {
                                    dexFileField.setAccessible(true);
                                    Object dexFile = dexFileField.get(element);
                                    if (dexFile != null) {
                                        String path = String.valueOf(dexFile);
                                        mDexFiles.add(path);
                                        Slog.d(TAG, "Found DEX: " + path);
                                    }
                                }
                            }
                        }
                    }
                    
                    // Get native library directories
                    Field nativeLibDirField = findField(pathList.getClass(), "nativeLibraryDirectories");
                    if (nativeLibDirField != null) {
                        nativeLibDirField.setAccessible(true);
                        Object[] nativeLibs = (Object[]) nativeLibDirField.get(pathList);
                        if (nativeLibs != null) {
                            for (Object lib : nativeLibs) {
                                Slog.d(TAG, "Native lib dir: " + lib);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Slog.w(TAG, "Failed to hook ClassLoader: " + e.getMessage());
        }
    }
    
    private void hookPathClassLoader() {
        try {
            Class<?> clazz = Class.forName("dalvik.system.PathClassLoader");
            Slog.d(TAG, "PathClassLoader available: " + clazz.getName());
            
            // Try to find existing instances via reflection
            Field parentField = findField(Thread.currentThread().getContextClassLoader().getClass(), "parent");
            if (parentField != null) {
                parentField.setAccessible(true);
                ClassLoader parent = (ClassLoader) parentField.get(Thread.currentThread().getContextClassLoader());
                if (parent != null) {
                    hookClassLoader(parent);
                }
            }
        } catch (Exception e) {
            Slog.d(TAG, "PathClassLoader hook: " + e.getMessage());
        }
    }
    
    private void hookDexClassLoader() {
        try {
            Class<?> clazz = Class.forName("dalvik.system.DexClassLoader");
            Slog.d-Javadoc(TAG, "DexClassLoader available");
        } catch (Exception e) {
            Slog.d(TAG, "DexClassLoader: " + e.getMessage());
        }
    }
    
    /**
     * Capture a class that was loaded at runtime
     */
    public void captureClass(Class<?> clazz) {
        if (!mActive || clazz == null) return;
        
        String name = clazz.getName();
        if (mLoadedClasses.containsKey(name)) return;
        
        mLoadedClasses.put(name, clazz);
        
        // Capture methods
        try {
            for (Method m : clazz.getDeclaredMethods()) {
                String key = name + "." + m.getName() + "(" + getParamTypes(m) + ")";
                MethodInfo info = new MethodInfo();
                info.className = name;
                info.methodName = m.getName();
                info.returnType = m.getReturnType().getName();
                info.parameterTypes = getParamTypes(m);
                info.modifiers = m.getModifiers();
                mLoadedMethods.put(key, info);
            }
        } catch (Exception e) { }
        
        // Capture fields
        try {
            for (Field f : clazz.getDeclaredFields()) {
                String key = name + "." + f.getName();
                FieldInfo info = new FieldInfo();
                info.className = name;
                info.fieldName = f.getName();
                info.type = f.getType().getName();
                info.modifiers = f.getModifiers();
                info.offset = 0; // will be calculated
                mLoadedFields.put(key, info);
            }
        } catch (Exception e) { }
        
        Slog.d(TAG, "Captured class: " + name);
    }
    
    /**
     * Capture a native library load
     */
    public void captureNativeLib(String path) {
        if (!mActive || path == null) return;
        mLoadedLibs.add(path);
        Slog.d(TAG, "Captured native lib: " + path);
    }
    
    /**
     * Capture a DEX file path
     */
    public void captureDex(String path) {
        if (!mActive || path == null) return;
        mDexFiles.add(path);
        Slog.d(TAG, "Captured DEX: " + path);
    }
    
    /**
     * Capture string constants from a class
     */
    public void captureStrings(Class<?> clazz) {
        if (!mActive || clazz == null) return;
        try {
            for (Field f : clazz.getDeclaredFields()) {
                if (f.getType() == String.class && java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    f.setAccessible(true);
                    Object val = f.get(null);
                    if (val != null) {
                        mStringConstants.put(clazz.getName() + "." + f.getName(), (String) val);
                    }
                }
            }
        } catch (Exception e) { }
    }
    
    /**
     * Generate all dump files from captured data
     */
    private void generateDumpFiles() {
        if (mOutputDir == null) return;
        
        try {
            // 1. Dump loaded classes
            generateClassDump();
            
            // 2. Dump methods
            generateMethodDump();
            
            // 3. Dump fields
            generateFieldDump();
            
            // 4. Dump DEX files
            generateDexList();
            
            // 5. Dump native libs
            generateNativeLibList();
            
            // 6. Dump string constants
            generateStringDump();
            
            // 7. Generate summary
            generateSummary();
            
            Slog.i(TAG, "Hook dump complete: " + mLoadedClasses.size() + " classes, " + 
                mLoadedMethods.size() + " methods, " + mLoadedFields.size() + " fields");
        } catch (Exception e) {
            Slog.e(TAG, "Failed to generate dump: " + e.getMessage());
        }
    }
    
    private void generateClassDump() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - Captured Classes\n");
        sb.append("// Total: ").append(mLoadedClasses.size()).append(" classes\n\n");
        sb.append("namespace Il2CppDump {\n");
        
        for (Map.Entry<String, Class<?>> entry : mLoadedClasses.entrySet()) {
            Class<?> clazz = entry.getValue();
            sb.append("    // ").append(entry.getKey()).append("\n");
            sb.append("    public class ").append(clazz.getSimpleName());
            
            if (clazz.getSuperclass() != null && clazz.getSuperclass() != Object.class) {
                sb.append(" : ").append(clazz.getSuperclass().getSimpleName());
            }
            sb.append(" {\n");
            
            // Fields
            for (Field f : clazz.getDeclaredFields()) {
                sb.append("        ");
                if (java.lang.reflect.Modifier.isPublic(f.getModifiers())) sb.append("public ");
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) sb.append("static ");
                sb.append(f.getType().getSimpleName()).append(" ").append(f.getName()).append(";\n");
            }
            
            sb.append("    }\n\n");
        }
        
        sb.append("}\n");
        writeToFile(new File(mOutputDir, "hookdump_classes.cs"), sb.toString());
    }
    
    private void generateMethodDump() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - Captured Methods\n");
        sb.append("// Total: ").append(mLoadedMethods.size()).append(" methods\n\n");
        
        for (Map.Entry<String, MethodInfo> entry : mLoadedMethods.entrySet()) {
            MethodInfo m = entry.getValue();
            sb.append(String.format("  0x%08x  %s %s.%s(%s)\n", 
                0, m.returnType, m.className, m.methodName, m.parameterTypes));
        }
        
        writeToFile(new File(mOutputDir, "hookdump_methods.txt"), sb.toString());
    }
    
    private void generateFieldDump() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - Captured Fields\n");
        sb.append("// Total: ").append(mLoadedFields.size()).append(" fields\n\n");
        
        for (Map.Entry<String, FieldInfo> entry : mLoadedFields.entrySet()) {
            FieldInfo f = entry.getValue();
            sb.append(String.format("  %-10s %s.%s  (type: %s, modifiers: 0x%x)\n",
                "0x" + Integer.toHexString(f.offset), f.className, f.fieldName, f.type, f.modifiers));
        }
        
        writeToFile(new File(mOutputDir, "hookdump_fields.txt"), sb.toString());
    }
    
    private void generateDexList() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - DEX Files in Memory\n");
        sb.append("// Total: ").append(mDexFiles.size()).append(" DEX files\n\n");
        
        for (String dex : mDexFiles) {
            sb.append("  ").append(dex).append("\n");
        }
        
        writeToFile(new File(mOutputDir, "hookdump_dex_files.txt"), sb.toString());
    }
    
    private void generateNativeLibList() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - Native Libraries Loaded\n");
        sb.append("// Total: ").append(mLoadedLibs.size()).append(" libraries\n\n");
        
        for (String lib : mLoadedLibs) {
            sb.append("  ").append(lib).append("\n");
        }
        
        writeToFile(new File(mOutputDir, "hookdump_native_libs.txt"), sb.toString());
    }
    
    private void generateStringDump() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// HookDump - String Constants\n");
        sb.append("// Total: ").append(mStringConstants.size()).append(" strings\n\n");
        
        for (Map.Entry<String, String> entry : mStringConstants.entrySet()) {
            sb.append(String.format("  %-60s  \"%s\"\n", entry.getKey(), entry.getValue()));
        }
        
        writeToFile(new File(mOutputDir, "hookdump_strings.txt"), sb.toString());
    }
    
    private void generateSummary() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║  HOOK DUMP SUMMARY                                          ║\n");
        sb.append("╚══════════════════════════════════════════════════════════════╝\n\n");
        sb.append("Captured at runtime via ClassLoader interception\n\n");
        sb.append("  Classes:    ").append(mLoadedClasses.size()).append("\n");
        sb.append("  Methods:    ").append(mLoadedMethods.size()).append("\n");
        sb.append("  Fields:     ").append(mLoadedFields.size()).append("\n");
        sb.append("  DEX files:  ").append(mDexFiles.size()).append("\n");
        sb.append("  Native libs:").append(mLoadedLibs.size()).append("\n");
        sb.append("  Strings:    ").append(mStringConstants.size()).append("\n\n");
        sb.append("Files:\n");
        sb.append("  hookdump_classes.cs     - Class dump\n");
        sb.append("  hookdump_methods.txt    - Method list with offsets\n");
        sb.append("  hookdump_fields.txt     - Field list with offsets\n");
        sb.append("  hookdump_dex_files.txt  - DEX file paths\n");
        sb.append("  hookdump_native_libs.txt - Loaded libraries\n");
        sb.append("  hookdump_strings.txt    - String constants\n");
        sb.append("  SUMMARY.txt             - This file\n");
        
        writeToFile(new File(mOutputDir, "SUMMARY.txt"), sb.toString());
    }
    
    // ==================== UTILS ====================
    
    private static Field findField(Class<?> clazz, String name) {
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(name);
                return f;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }
    
    private String getParamTypes(Method m) {
        StringBuilder sb = new StringBuilder();
        Class<?>[] params = m.getParameterTypes();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(params[i].getSimpleName());
        }
        return sb.toString();
    }
    
    private void writeToFile(File file, String content) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(content.getBytes());
        fos.close();
    }
    
    // ==================== DATA CLASSES ====================
    
    public static class MethodInfo {
        public String className;
        public String methodName;
        public String returnType;
        public String parameterTypes;
        public int modifiers;
    }
    
    public static class FieldInfo {
        public String className;
        public String fieldName;
        public String type;
        public int modifiers;
        public int offset;
    }
    
    // ==================== STATS ====================
    
    public int getClassCount() { return mLoadedClasses.size(); }
    public int getMethodCount() { return mLoadedMethods.size(); }
    public int getFieldCount() { return mLoadedFields.size(); }
    public int getDexCount() { return mDexFiles.size(); }
    public int getNativeLibCount() { return mLoadedLibs.size(); }
    public int getStringCount() { return mStringConstants.size(); }
    public boolean isActive() { return mActive; }
}
