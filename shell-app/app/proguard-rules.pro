# ---- Manifest entry points (class name must survive) ----
-keep class com.enko.shell.ProxyApplication {
    # Framework calls: must keep exact signatures.
    void attachBaseContext(android.content.Context);
    void onCreate();
}
-keep class com.enko.shell.EnkoInitProvider {
    boolean onCreate();
}

# ---- JNI bridge: native method signatures are baked into libagpcore.so ----
-keep class com.enko.shell.NativeBridge {
    native <methods>;
    static boolean isAvailable();
}

# ---- Public runtime API the hosted app queries for graded risk (P6-1) ----
-keep class com.enko.shell.EnkoRuntime {
    public static *;
}

# ---- Everything else is internal — allow full obfuscation ----
-keepclassmembers class * {
    # Preserve Serializable if any
    private static final java.io.ObjectStreamField[] serialPersistentFields;
}

# ---- Hard obfuscation profile for shell Java code ----
-allowaccessmodification
-repackageclasses
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents **.xml,**.json,**.txt,**.properties
-overloadaggressively
-obfuscationdictionary proguard-dict-members.txt
-classobfuscationdictionary proguard-dict-classes.txt
-packageobfuscationdictionary proguard-dict-packages.txt
-renamesourcefileattribute .
-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault,Signature,InnerClasses,EnclosingMethod

# Suppress warnings for internal-only reflection we control.
-dontwarn com.enko.shell.**

# Optimisation: remove logging in release.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
}
