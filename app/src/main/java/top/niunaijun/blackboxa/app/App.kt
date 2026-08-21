package top.niunaijun.blackboxa.app

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.os.Build
import android.util.Log
import top.niunaijun.blackbox.BlackBoxCore

/**
 * BlackBox Enhanced v0.0.10
 * Enhanced by Panxcz & Freebuff
 */
class App : Application() {

    companion object {
        private const val TAG = "BlackBoxApp"

        @SuppressLint("StaticFieldLeak")
        @Volatile
        private lateinit var mContext: Context

        @JvmStatic
        fun getContext(): Context {
            return mContext
        }
    }

    override fun attachBaseContext(base: Context?) {
        try {
            Log.i(TAG, "===========================================")
            Log.i(TAG, "BlackBox Enhanced v0.0.10 Starting")
            Log.i(TAG, "Device: ${Build.BRAND} ${Build.MODEL}")
            Log.i(TAG, "Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            Log.i(TAG, "===========================================")

            super.attachBaseContext(base)

            try {
                BlackBoxCore.get().closeCodeInit()
                Log.d(TAG, "closeCodeInit: OK")
            } catch (e: Exception) {
                Log.e(TAG, "closeCodeInit FAILED: ${e.message}")
            }

            try {
                BlackBoxCore.get().onBeforeMainApplicationAttach(this, base)
                Log.d(TAG, "onBeforeMainApplicationAttach: OK")
            } catch (e: Exception) {
                Log.e(TAG, "onBeforeMainApplicationAttach FAILED: ${e.message}")
            }

            mContext = base!!

            try {
                AppManager.doAttachBaseContext(base)
                Log.d(TAG, "doAttachBaseContext: OK")
            } catch (e: Exception) {
                Log.e(TAG, "doAttachBaseContext FAILED: ${e.message}")
            }

            try {
                BlackBoxCore.get().onAfterMainApplicationAttach(this, base)
                Log.d(TAG, "onAfterMainApplicationAttach: OK")
            } catch (e: Exception) {
                Log.e(TAG, "onAfterMainApplicationAttach FAILED: ${e.message}")
            }

            Log.i(TAG, "attachBaseContext completed successfully")
        } catch (e: Exception) {
            Log.e(TAG, "CRITICAL ERROR in attachBaseContext: ${e.message}", e)
            if (base != null) {
                mContext = base
            }
        }
    }

    override fun onCreate() {
        try {
            super.onCreate()
            Log.i(TAG, "onCreate: Initializing...")
            AppManager.doOnCreate(mContext)
            Log.i(TAG, "onCreate: OK - BlackBox Enhanced ready!")
            Log.i(TAG, "===========================================")
        } catch (e: Exception) {
            Log.e(TAG, "onCreate FAILED: ${e.message}", e)
        }
    }
}
