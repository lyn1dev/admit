from decimal import Decimal

from invoice_utils.totals import apply_tax, format_eur, subtotal


def test_subtotal_rounds_to_cents():
    assert subtotal([Decimal("19.99"), Decimal("5.00")]) == Decimal("24.99")


def test_apply_tax_default_rate():
    assert apply_tax(Decimal("100.00")) == Decimal("123.00")


def test_format_eur_uses_thousands_separator():
    assert format_eur(Decimal("1234.5")) == "€1,234.50"
