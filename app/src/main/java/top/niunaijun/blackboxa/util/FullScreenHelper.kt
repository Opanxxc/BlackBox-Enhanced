package top.niunaijun.blackboxa.util

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager

@Suppress("DEPRECATION")
object FullScreenHelper {

    private const val TAG = "FullScreenHelper"

    fun enableImmersive(activity: Activity) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                activity.window.insetsController?.let { controller ->
                    controller.hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                    controller.systemBarsBehavior =
                        WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
                } ?: run {
                    Log.w(TAG, "insetsController null, using legacy flags")
                    setLegacyFlags(activity)
                }
            } else {
                setLegacyFlags(activity)
            }

            activity.window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            activity.window.statusBarColor = Color.TRANSPARENT
            activity.window.navigationBarColor = Color.TRANSPARENT

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                activity.window.attributes.layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }

            Log.d(TAG, "Immersive enabled for ${activity.javaClass.simpleName}")
        } catch (e: Exception) {
            Log.e(TAG, "Error enabling immersive: ${e.message}")
        }
    }

    private fun setLegacyFlags(activity: Activity) {
        try {
            activity.window.decorView.systemUiVisibility = (
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
                activity.window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_VISIBLE
            }

            activity.window.statusBarColor = Color.BLACK
            activity.window.navigationBarColor = Color.BLACK
        } catch (e: Exception) {
            Log.e(TAG, "Error disabling immersive: ${e.message}")
        }
    }
}
