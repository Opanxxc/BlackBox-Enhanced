package top.niunaijun.blackbox.core.system.shell;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.utils.CloseUtils;
import top.niunaijun.blackbox.utils.FileUtils;
import top.niunaijun.blackbox.utils.Slog;

/**
 * Service for executing shell scripts (.sh) within the virtual environment.
 * Supports running scripts with arguments, environment variables, and working directory.
 */
public class ShellScriptService implements ISystemService {
    public static final String TAG = "ShellScriptService";
    
    private static final ShellScriptService sService = new ShellScriptService();
    private final Executor mThreadPool = Executors.newCachedThreadPool();
    private final Map<Integer, ScriptSession> mSessions = new HashMap<>();
    private int mNextSessionId = 1;
    
    public static ShellScriptService get() {
        return sService;
    }
    
    /**
     * Execute a shell script file
     * @param scriptPath Path to the .sh file
     * @param args Arguments to pass to the script
     * @param envVars Environment variables to set
     * @param workingDir Working directory
     * @param callback Callback for script output
     * @return Session ID for tracking
     */
    public int executeScript(String scriptPath, String[] args, Map<String, String> envVars, 
                           String workingDir, IScriptCallback callback) {
        int sessionId = mNextSessionId++;
        ScriptSession session = new ScriptSession(sessionId, scriptPath, args, envVars, workingDir, callback);
        mSessions.put(sessionId, session);
        
        mThreadPool.execute(() -> {
            try {
                session.run();
            } finally {
                mSessions.remove(sessionId);
            }
        });
        
        return sessionId;
    }
    
    /**
     * Execute a shell script from content string
     * @param scriptContent Content of the script
     * @param scriptName Name for the script file
     * @param args Arguments to pass to the script
     * @param envVars Environment variables to set
     * @param workingDir Working directory
     * @param callback Callback for script output
     * @return Session ID for tracking
     */
    public int executeScriptContent(String scriptContent, String scriptName, String[] args, 
                                  Map<String, String> envVars, String workingDir, 
                                  IScriptCallback callback) {
        int sessionId = mNextSessionId++;
        ScriptSession session = new ScriptSession(sessionId, scriptContent, scriptName, args, envVars, workingDir, callback);
        mSessions.put(sessionId, session);
        
        mThreadPool.execute(() -> {
            try {
                session.runFromContent();
            } finally {
                mSessions.remove(sessionId);
            }
        });
        
        return sessionId;
    }
    
    /**
     * Kill a running script session
     * @param sessionId Session ID to kill
     */
    public void killSession(int sessionId) {
        ScriptSession session = mSessions.get(sessionId);
        if (session != null) {
            session.kill();
        }
    }
    
    /**
     * Get session status
     * @param sessionId Session ID
     * @return Session status
     */
    public ScriptSession.Status getSessionStatus(int sessionId) {
        ScriptSession session = mSessions.get(sessionId);
        if (session != null) {
            return session.getStatus();
        }
        return ScriptSession.Status.NOT_FOUND;
    }
    
    /**
     * Check if a file is a valid shell script
     * @param filePath Path to check
     * @return true if the file appears to be a shell script
     */
    public boolean isShellScript(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.canRead()) {
            return false;
        }
        
        // Check file extension
        if (filePath.endsWith(".sh") || filePath.endsWith(".bash") || filePath.endsWith(".zsh")) {
            return true;
        }
        
        // Check shebang
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(file)));
            String firstLine = reader.readLine();
            reader.close();
            
            if (firstLine != null && firstLine.startsWith("#!")) {
                String interpreter = firstLine.substring(2).trim();
                return interpreter.contains("sh") || interpreter.contains("bash") || 
                       interpreter.contains("zsh") || interpreter.contains("env");
            }
        } catch (IOException e) {
            // Ignore
        }
        
        return false;
    }
    
    @Override
    public void systemReady() {
        // Initialize shell script service
        Slog.d(TAG, "ShellScriptService initialized");
    }
    
    /**
     * Script session class
     */
    public static class ScriptSession {
        private final int mSessionId;
        private final String mScriptPath;
        private final String mScriptContent;
        private final String mScriptName;
        private final String[] mArgs;
        private final Map<String, String> mEnvVars;
        private final String mWorkingDir;
        private final IScriptCallback mCallback;
        private Process mProcess;
        private volatile Status mStatus = Status.RUNNING;
        
        public enum Status {
            RUNNING,
            COMPLETED,
            ERROR,
            KILLED,
            NOT_FOUND
        }
        
        public ScriptSession(int sessionId, String scriptPath, String[] args, 
                           Map<String, String> envVars, String workingDir, 
                           IScriptCallback callback) {
            this.mSessionId = sessionId;
            this.mScriptPath = scriptPath;
            this.mScriptContent = null;
            this.mScriptName = null;
            this.mArgs = args;
            this.mEnvVars = envVars;
            this.mWorkingDir = workingDir;
            this.mCallback = callback;
        }
        
        public ScriptSession(int sessionId, String scriptContent, String scriptName, 
                           String[] args, Map<String, String> envVars, String workingDir, 
                           IScriptCallback callback) {
            this.mSessionId = sessionId;
            this.mScriptPath = null;
            this.mScriptContent = scriptContent;
            this.mScriptName = scriptName;
            this.mArgs = args;
            this.mEnvVars = envVars;
            this.mWorkingDir = workingDir;
            this.mCallback = callback;
        }
        
        public void run() {
            try {
                File scriptFile = new File(mScriptPath);
                if (!scriptFile.exists()) {
                    mStatus = Status.ERROR;
                    if (mCallback != null) {
                        mCallback.onError(mSessionId, "Script file not found: " + mScriptPath);
                    }
                    return;
                }
                
                // Make script executable
                scriptFile.setExecutable(true, false);
                
                // Build command
                String[] command = buildCommand(mScriptPath);
                
                // Execute script
                executeProcess(command);
                
            } catch (Exception e) {
                mStatus = Status.ERROR;
                if (mCallback != null) {
                    mCallback.onError(mSessionId, e.getMessage());
                }
            }
        }
        
        public void runFromContent() {
            try {
                // Create temporary script file
                File tempDir = new File(BEnvironment.getDataDir(), "scripts");
                tempDir.mkdirs();
                
                File scriptFile = new File(tempDir, mScriptName != null ? mScriptName : "script_" + mSessionId + ".sh");
                FileUtils.writeToFile(mScriptContent.getBytes(), scriptFile);
                scriptFile.setExecutable(true, false);
                
                // Build command
                String[] command = buildCommand(scriptFile.getAbsolutePath());
                
                // Execute script
                executeProcess(command);
                
                // Cleanup
                scriptFile.delete();
                
            } catch (Exception e) {
                mStatus = Status.ERROR;
                if (mCallback != null) {
                    mCallback.onError(mSessionId, e.getMessage());
                }
            }
        }
        
        private String[] buildCommand(String scriptPath) {
            // Build command with arguments
            int totalLength = 2 + (mArgs != null ? mArgs.length : 0); // sh + script + args
            String[] command = new String[totalLength];
            command[0] = "/system/bin/sh";
            command[1] = scriptPath;
            
            if (mArgs != null) {
                System.arraycopy(mArgs, 0, command, 2, mArgs.length);
            }
            
            return command;
        }
        
        private void executeProcess(String[] command) throws IOException {
            // Build process builder
            ProcessBuilder pb = new ProcessBuilder(command);
            
            // Set working directory
            if (mWorkingDir != null) {
                pb.directory(new File(mWorkingDir));
            } else {
                pb.directory(new File(BEnvironment.getDataDir()));
            }
            
            // Set environment variables
            Map<String, String> env = pb.environment();
            if (mEnvVars != null) {
                env.putAll(mEnvVars);
            }
            
            // Add virtual environment variables
            env.put("VIRTUAL_ENV", "1");
            env.put("BLACKBOX_ENV", "1");
            env.put("HOME", BEnvironment.getDataDir().getAbsolutePath());
            env.put("TMPDIR", new File(BEnvironment.getDataDir(), "tmp").getAbsolutePath());
            
            // Redirect error stream
            pb.redirectErrorStream(true);
            
            // Start process
            mProcess = pb.start();
            
            // Read output
            BufferedReader reader = new BufferedReader(new InputStreamReader(mProcess.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (mCallback != null) {
                    mCallback.onOutput(mSessionId, line);
                }
            }
            
            // Wait for process to complete
            int exitCode = mProcess.waitFor();
            
            if (exitCode == 0) {
                mStatus = Status.COMPLETED;
                if (mCallback != null) {
                    mCallback.onCompleted(mSessionId, exitCode);
                }
            } else {
                mStatus = Status.ERROR;
                if (mCallback != null) {
                    mCallback.onError(mSessionId, "Script exited with code: " + exitCode);
                }
            }
            
            reader.close();
        }
        
        public void kill() {
            if (mProcess != null) {
                mProcess.destroy();
                mStatus = Status.KILLED;
            }
        }
        
        public Status getStatus() {
            return mStatus;
        }
        
        public int getSessionId() {
            return mSessionId;
        }
    }
    
    /**
     * Callback interface for script execution
     */
    public interface IScriptCallback {
        void onOutput(int sessionId, String line);
        void onCompleted(int sessionId, int exitCode);
        void onError(int sessionId, String error);
    }
}
