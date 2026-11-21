"""Invoice arithmetic."""

from collections.abc import Iterable
from decimal import ROUND_HALF_UP, Decimal

DEFAULT_TAX_RATE = Decimal("0.23")


def subtotal(amounts: Iterable[Decimal | float | int]) -> Decimal:
    """Sum line amounts, rounded to cents."""
    total = sum((Decimal(str(a)) for a in amounts), Decimal("0"))
    return total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def apply_tax(amount: Decimal, rate: Decimal = DEFAULT_TAX_RATE) -> Decimal:
    """Return amount plus tax, rounded to cents."""
    return (amount * (1 + rate)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def format_eur(amount: Decimal) -> str:
    """Format an amount as a euro string, e.g. 1234.5 -> '€1,234.50'."""
    return "€" + f"{amount:,.2f}"
