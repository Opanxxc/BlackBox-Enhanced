# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-keep class top.niunaijun.blackbox.** {*; }
-keep class top.niunaijun.blackboxa.** {*; }
-keep class top.niunaijun.jnihook.** {*; }
-keep class mirror.** {*; }
-keep class android.** {*; }
-keep class com.android.** {*; }

# Keep our custom services
-keep class top.niunaijun.blackbox.core.system.dumper.** {*; }
-keep class top.niunaijun.blackbox.core.system.shell.** {*; }
-keep class top.niunaijun.blackbox.core.system.auth.** {*; }
-keep class top.niunaijun.blackbox.core.system.hideroot.** {*; }
-keep class top.niunaijun.blackbox.core.system.hidevpn.** {*; }
-keep class top.niunaijun.blackbox.core.system.integrity.** {*; }
-keep class top.niunaijun.blackbox.core.system.bypass.** {*; }
-keep class top.niunaijun.blackbox.core.system.location.** {*; }

# Keep data classes and view models
-keep class top.niunaijun.blackboxa.bean.** {*; }
-keep class top.niunaijun.blackboxa.data.** {*; }
-keep class top.niunaijun.blackboxa.view.gms.** {*; }
-keep class top.niunaijun.blackboxa.view.setting.** {*; }
-keep class top.niunaijun.blackboxa.view.base.** {*; }
-keep class top.niunaijun.blackboxa.view.apps.** {*; }
-keep class top.niunaijun.blackboxa.view.main.** {*; }
-keep class top.niunaijun.blackboxa.util.** {*; }

# Keep full screen helper
-keep class top.niunaijun.blackboxa.util.FullScreenHelper {*; }

# Keep Material Dialogs
-keep class com.afollestad.materialdialogs.** {*; }

-keep class top.niunaijun.blackreflection.** {*; }
-keep @top.niunaijun.blackreflection.annotation.BClass class * {*;}
-keep @top.niunaijun.blackreflection.annotation.BClassName class * {*;}
-keep @top.niunaijun.blackreflection.annotation.BClassNameNotProcess class * {*;}
-keepclasseswithmembernames class * {
    @top.niunaijun.blackreflection.annotation.BField.* <methods>;
    @top.niunaijun.blackreflection.annotation.BFieldNotProcess.* <methods>;
    @top.niunaijun.blackreflection.annotation.BFieldSetNotProcess.* <methods>;
    @top.niunaijun.blackreflection.annotation.BFieldCheckNotProcess.* <methods>;
    @top.niunaijun.blackreflection.annotation.BMethod.* <methods>;
    @top.niunaijun.blackreflection.annotation.BStaticField.* <methods>;
    @top.niunaijun.blackreflection.annotation.BStaticMethod.* <methods>;
    @top.niunaijun.blackreflection.annotation.BMethodCheckNotProcess.* <methods>;
    @top.niunaijun.blackreflection.annotation.BConstructor.* <methods>;
    @top.niunaijun.blackreflection.annotation.BConstructorNotProcess.* <methods>;
}