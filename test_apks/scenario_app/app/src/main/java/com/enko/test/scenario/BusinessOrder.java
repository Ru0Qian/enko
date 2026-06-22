package com.enko.test.scenario;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class BusinessOrder {
    public static final class Line {
        public final String sku;
        public final int quantity;
        public final int unitCents;

        Line(String sku, int quantity, int unitCents) {
            this.sku = sku;
            this.quantity = quantity;
            this.unitCents = unitCents;
        }

        int subtotalCents() {
            return quantity * unitCents;
        }
    }

    private final List<Line> lines;
    private final String couponCode;

    BusinessOrder(List<Line> lines, String couponCode) {
        this.lines = new ArrayList<>(lines);
        this.couponCode = couponCode;
    }

    List<Line> lines() {
        return Collections.unmodifiableList(lines);
    }

    String couponCode() {
        return couponCode;
    }
}
