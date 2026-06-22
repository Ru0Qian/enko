package com.enko.test.large;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

public class TestProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        Log.i("TestProvider", "onCreate");
        return true;
    }
    @Override
    public Cursor query(Uri uri, String[] p, String s, String[] a, String sort) { return null; }
    @Override
    public String getType(Uri uri) { return null; }
    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override
    public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override
    public int update(Uri uri, ContentValues v, String s, String[] a) { return 0; }
}
