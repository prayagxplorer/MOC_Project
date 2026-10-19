from itertools import product

ALPHABET = ("PK", "CT", "CONF_A", "CONF_B")
INIT = "init"
KEY_SENT = "key-sent"
CIPHERTEXT_RECEIVED = "ciphertext-received"
CONFIRMED = "confirmed"
ESTABLISHED = "established"
REJECT = "reject"
STATES = (INIT, KEY_SENT, CIPHERTEXT_RECEIVED, CONFIRMED, ESTABLISHED, REJECT)
ACCEPTING_STATES = frozenset({ESTABLISHED})

TRANSITIONS = {
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
    def __init__(self, previous_state, symbol):
        self.previous_state = previous_state
        self.symbol = symbol
        super().__init__(f"DFA rejected {symbol!r} at {previous_state!r}")


class HandshakeDFA:
    def __init__(self, state=INIT, transitions=None):
        if state not in STATES:
            raise ValueError(f"Unknown initial state: {state!r}")
        self.state = state
        self.transitions = TRANSITIONS if transitions is None else transitions

    @property
    def accepted(self):
        return self.state in ACCEPTING_STATES

    def step(self, symbol):
        previous_state = self.state
        # Symbols outside the alphabet enter the implicit dead state too.
        self.state = self.transitions.get((self.state, symbol), REJECT)
        if self.state == REJECT:
            raise DFARejection(previous_state, symbol)
        return self.state


def accepts(trace):
    state = INIT
    for symbol in trace:
        state = TRANSITIONS.get((state, symbol), REJECT)
    return state in ACCEPTING_STATES


if __name__ == "__main__":
    checked, accepted = 0, []
    for length in range(7):
        for trace in product(ALPHABET, repeat=length):
            checked += 1
            if accepts(trace):
                accepted.append(trace)
    assert checked == 5461
    assert accepted == [("PK", "CT", "CONF_A", "CONF_B")]
    assert len(TRANSITIONS) == len(STATES) * len(ALPHABET) == 24
    assert all(TRANSITIONS[REJECT, symbol] == REJECT for symbol in ALPHABET)
    assert not accepts(["INVALID"])
    print(f"{checked} strings checked; language verified")
