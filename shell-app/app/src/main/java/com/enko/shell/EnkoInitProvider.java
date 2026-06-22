package com.enko.shell;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

/**
 * Empty ContentProvider whose sole purpose is to trigger native library
 * loading at the earliest possible point in the application lifecycle.
 *
 * <p>Android instantiates ContentProviders before {@code Application.attachBaseContext}.
 * By loading the native library here, we ensure:
 * <ol>
 *   <li>{@code .init_array} constructor fires before any Java code</li>
 *   <li>{@code JNI_OnLoad} starts the anti-debug watchdog immediately</li>
 *   <li>ptrace(TRACEME) claims the tracer slot before a debugger can</li>
 * </ol>
 *
 * <p>Declared in AndroidManifest.xml with
 * {@code authorities="${applicationId}.enko_init"}.
 */
public final class EnkoInitProvider extends ContentProvider {

    @Override
    public boolean onCreate() {
        /* Touching NativeBridge triggers its static initializer which
         * calls System.loadLibrary("agpcore"). */
        boolean ready = NativeBridge.isAvailable();
        /* No-op return — this provider serves no content. */
        return ready;
    }

    /* ---- All content methods are no-ops ---- */

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        return 0;
    }
}
