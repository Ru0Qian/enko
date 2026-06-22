# Demo app custom R8/ProGuard rules.
# Keep minimal by default; Android components are retained from manifest.

# Keep stable symbols for Enko method-level protection map (extract/vmp/dex2c).
# Other classes/members can still be shrunk/obfuscated.
-keep class com.example.demo.MainActivity { *; }
-keep class com.example.demo.CryptoHelper { *; }
-keep class com.example.demo.LicenseManager { *; }
