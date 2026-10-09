"""Executable DFA for the Review 1 ML-KEM handshake.

The transition table below is deliberately complete: every state/symbol pair
has an entry.  This lets protocol code use one source of truth for ordering
and makes every unexpected message move the machine to ``reject``.
"""

from __future__ import annotations

from dataclasses import dataclass

ALPHABET = ("PK", "CT", "CONF_A", "CONF_B")
INIT = "init"
KEY_SENT = "key-sent"
CIPHERTEXT_RECEIVED = "ciphertext-received"
CONFIRMED = "confirmed"
ESTABLISHED = "established"
REJECT = "reject"

STATES = (INIT, KEY_SENT, CIPHERTEXT_RECEIVED, CONFIRMED, ESTABLISHED, REJECT)
ACCEPTING_STATES = frozenset({ESTABLISHED})

# The sole source of truth for legal message ordering.
TRANSITIONS: dict[tuple[str, str], str] = {
    (INIT, "PK"): KEY_SENT,
    (INIT, "CT"): REJECT,
    (INIT, "CONF_A"): REJECT,
    (INIT, "CONF_B"): REJECT,
    (KEY_SENT, "PK"): REJECT,
    (KEY_SENT, "CT"): CIPHERTEXT_RECEIVED,
    (KEY_SENT, "CONF_A"): REJECT,
    (KEY_SENT, "CONF_B"): REJECT,
    (CIPHERTEXT_RECEIVED, "PK"): REJECT,
    (CIPHERTEXT_RECEIVED, "CT"): REJECT,
    (CIPHERTEXT_RECEIVED, "CONF_A"): CONFIRMED,
    (CIPHERTEXT_RECEIVED, "CONF_B"): REJECT,
    (CONFIRMED, "PK"): REJECT,
    (CONFIRMED, "CT"): REJECT,
    (CONFIRMED, "CONF_A"): REJECT,
    (CONFIRMED, "CONF_B"): ESTABLISHED,
    (ESTABLISHED, "PK"): REJECT,
    (ESTABLISHED, "CT"): REJECT,
    (ESTABLISHED, "CONF_A"): REJECT,
    (ESTABLISHED, "CONF_B"): REJECT,
    (REJECT, "PK"): REJECT,
    (REJECT, "CT"): REJECT,
    (REJECT, "CONF_A"): REJECT,
    (REJECT, "CONF_B"): REJECT,
}


class DFARejection(RuntimeError):
    """Raised when an input is not legal at the DFA's current state."""

    def __init__(self, previous_state: str, symbol: str) -> None:
        self.previous_state = previous_state
        self.symbol = symbol
        super().__init__(
            f"DFA rejected {symbol!r}: state was {previous_state!r}; "
            f"new state is {REJECT!r}."
        )


@dataclass
class HandshakeDFA:
    """A mutable recognizer for one handshake transcript."""

    state: str = INIT
    transitions: dict[tuple[str, str], str] | None = None

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError(f"Unknown initial state: {self.state!r}")
        if self.transitions is None:
            # Kept as an attribute so prototype code can inspect/use the table.
            self.transitions = TRANSITIONS

    @property
    def accepted(self) -> bool:
        return self.state in ACCEPTING_STATES

    def step(self, symbol: str) -> str:
        """Consume *symbol*, or enter ``reject`` and raise DFARejection.

        Code performing a cryptographic action should call this method first.
        Therefore an invalid transition cannot trigger that action.
        """
        if symbol not in ALPHABET:
            raise ValueError(f"Unknown DFA symbol: {symbol!r}")

        previous_state = self.state
        # ``transitions`` is always set by __post_init__.
        self.state = self.transitions[(previous_state, symbol)]  # type: ignore[index]
        if self.state == REJECT:
            raise DFARejection(previous_state, symbol)
        return self.state
