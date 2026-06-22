package com.enko.test.scenario;

public final class PricingEngine {
    static final class Quote {
        final int subtotalCents;
        final int discountCents;
        final int taxCents;
        final int totalCents;

        Quote(int subtotalCents, int discountCents, int taxCents, int totalCents) {
            this.subtotalCents = subtotalCents;
            this.discountCents = discountCents;
            this.taxCents = taxCents;
            this.totalCents = totalCents;
        }
    }

    Quote quote(BusinessOrder order) {
        int subtotal = 0;
        for (BusinessOrder.Line line : order.lines()) {
            subtotal += line.subtotalCents();
        }

        int discount = 0;
        if ("ENKO26".equals(order.couponCode())) {
            discount = (subtotal * 13) / 100;
        }

        int taxable = Math.max(0, subtotal - discount);
        int tax = (taxable * 875 + 9999) / 10000;
        int service = order.lines().size() * 37;
        return new Quote(subtotal, discount, tax, taxable + tax + service);
    }

    int stabilityCode(Quote quote) {
        int v = quote.totalCents;
        v ^= quote.subtotalCents * 31;
        v ^= quote.discountCents * 17;
        v ^= quote.taxCents * 7;
        return v & 0x7FFFFFFF;
    }
}
