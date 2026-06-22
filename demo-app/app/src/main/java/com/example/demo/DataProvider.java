package com.example.demo;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

/**
 * ContentProvider that exposes non-sensitive app metadata.
 * Demonstrates provider-based data sharing for hardening validation.
 */
public class DataProvider extends ContentProvider {
    private static final String AUTHORITY = "com.example.demo.provider";
    private static final int CODE_STATUS = 1;
    private static final int CODE_VERSION = 2;
    private static final UriMatcher matcher = new UriMatcher(UriMatcher.NO_MATCH);

    static {
        matcher.addURI(AUTHORITY, "status", CODE_STATUS);
        matcher.addURI(AUTHORITY, "version", CODE_VERSION);
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        switch (matcher.match(uri)) {
            case CODE_STATUS: {
                MatrixCursor c = new MatrixCursor(new String[]{"key", "value"});
                c.addRow(new Object[]{"app", "running"});
                c.addRow(new Object[]{"pid", String.valueOf(android.os.Process.myPid())});
                c.addRow(new Object[]{"crypto", verifyCrypto() ? "ok" : "fail"});
                return c;
            }
            case CODE_VERSION: {
                MatrixCursor c = new MatrixCursor(new String[]{"version_name", "version_code"});
                c.addRow(new Object[]{"1.0", 1});
                return c;
            }
            default:
                return null;
        }
    }

    private boolean verifyCrypto() {
        try {
            CryptoHelper crypto = new CryptoHelper();
            return "test".equals(crypto.decrypt(crypto.encrypt("test")));
        } catch (Exception e) {
            return false;
        }
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.dir/vnd.demo.data"; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
