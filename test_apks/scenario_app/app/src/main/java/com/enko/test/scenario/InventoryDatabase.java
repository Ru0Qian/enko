package com.enko.test.scenario;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

public final class InventoryDatabase extends SQLiteOpenHelper {
    private static final String DB_NAME = "business_matrix.db";
    private static final int DB_VERSION = 1;

    InventoryDatabase(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE inventory (sku TEXT PRIMARY KEY, cents INTEGER NOT NULL, stock INTEGER NOT NULL)");
        insert(db, "SKU-CORE", 1299, 9);
        insert(db, "SKU-PLUS", 2499, 5);
        insert(db, "SKU-AUDIT", 799, 11);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS inventory");
        onCreate(db);
    }

    BusinessOrder buildOrder() {
        SQLiteDatabase db = getReadableDatabase();
        List<BusinessOrder.Line> lines = new ArrayList<>();
        addLine(db, lines, "SKU-CORE", 2);
        addLine(db, lines, "SKU-PLUS", 1);
        addLine(db, lines, "SKU-AUDIT", 3);
        return new BusinessOrder(lines, "ENKO26");
    }

    private static void insert(SQLiteDatabase db, String sku, int cents, int stock) {
        ContentValues values = new ContentValues();
        values.put("sku", sku);
        values.put("cents", cents);
        values.put("stock", stock);
        db.insert("inventory", null, values);
    }

    private static void addLine(SQLiteDatabase db, List<BusinessOrder.Line> lines, String sku, int quantity) {
        try (Cursor cursor = db.query(
                "inventory",
                new String[] {"cents", "stock"},
                "sku=?",
                new String[] {sku},
                null,
                null,
                null)) {
            if (!cursor.moveToFirst()) {
                throw new IllegalStateException("missing sku " + sku);
            }
            int unitCents = cursor.getInt(0);
            int stock = cursor.getInt(1);
            if (stock < quantity) {
                throw new IllegalStateException("stock exhausted " + sku);
            }
            lines.add(new BusinessOrder.Line(sku, quantity, unitCents));
        }
    }
}
