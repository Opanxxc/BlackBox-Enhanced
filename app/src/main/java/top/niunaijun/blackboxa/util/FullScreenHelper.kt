package top.niunaijun.blackboxa.util

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager

/**
 * Game-like immersive fullscreen helper.
 * - Hides status bar + navigation bar completely
 * - Swipe from top/bottom edges to temporarily reveal system bars (transient)
 * - Content draws edge-to-edge behind system bars
 * - Supports notch/cutout display
 */
object FullScreenHelper {

    private const val TAG = "FullScreenHelper"

    fun enableImmersive(activity: Activity) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Android 11+ (API 30+): WindowInsetsController
                activity.window.setDecorFitsSystemWindows(false)
                activity.window.insetsController?.let { controller ->
                    controller.hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                    controller.systemBarsBehavior =
                        WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
                } ?: run {
                    Log.w(TAG, "insetsController is null, falling back to legacy flags")
                    setLegacyFlags(activity)
                }
            } else {
                setLegacyFlags(activity)
            }

            // Transparent system bars + draw behind
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                activity.window.statusBarColor = Color.TRANSPARENT
                activity.window.navigationBarColor = Color.TRANSPARENT
            }

            // Draw behind notch / display cutout
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                activity.window.attributes.layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }

            Log.d(TAG, "Immersive fullscreen enabled for ${activity.javaClass.simpleName}")
        } catch (e: Exception) {
            Log.e(TAG, "Error enabling immersive: ${e.message}")
        }
    }

    @Suppress("DEPRECATION")
    private fun setLegacyFlags(activity: Activity) {
        try {
            activity.window.decorView?.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                    or View.SYSTEM_UI_FLAG_FULLSCREEN
                    or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                    or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error setting legacy flags: ${e.message}")
        }
    }

    fun disableImmersive(activity: Activity) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                activity.window.insetsController?.let { controller ->
                    controller.show(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                }
            } else {
                @Suppress("DEPRECATION")
                activity.window.decorView?.systemUiVisibility = View.SYSTEM_UI_FLAG_VISIBLE
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                activity.window.statusBarColor = Color.BLACK
                activity.window.navigationBarColor = Color.BLACK
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error disabling immersive: ${e.message}")
        }
    }
}
