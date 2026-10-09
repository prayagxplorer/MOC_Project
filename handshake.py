"""In-process, DFA-gated ML-KEM-512 handshake.

This is intentionally a single-process demonstration.  ``PartyA`` and
``PartyB`` are logical parties; no socket or network code is involved.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
from hashlib import sha256
from typing import Callable, TypeVar

from kyber_py.ml_kem import ML_KEM_512

from dfa_spec import HandshakeDFA

T = TypeVar("T")


@dataclass(frozen=True)
class Message:
    """A typed in-process message; ``kind`` is exactly one DFA symbol."""

    kind: str
    payload: bytes


@dataclass
class PartyA:
    public_key: bytes | None = None
    private_key: bytes | None = None
    shared_secret: bytes | None = None


@dataclass
class PartyB:
    shared_secret: bytes | None = None


class InProcessHandshake:
    """Coordinates the two parties and gates each operation through one DFA."""

    def __init__(self) -> None:
        self.dfa = HandshakeDFA()
        self.party_a = PartyA()
        self.party_b = PartyB()

    def _authorized(self, symbol: str, action: Callable[[], T]) -> T:
        """Authorize a message type before running its matching crypto action."""
        self.dfa.step(symbol)
        return action()

    def send_public_key(self) -> Message:
        """A generates its ML-KEM key pair and sends the public encapsulation key."""
        def create_pk() -> Message:
            public_key, private_key = ML_KEM_512.keygen()
            self.party_a.public_key = public_key
            self.party_a.private_key = private_key
            return Message("PK", public_key)

        return self._authorized("PK", create_pk)

    def send_ciphertext(self, public_key_message: Message) -> Message:
        """B encapsulates to A's supplied public key, producing CT and its secret."""
        if public_key_message.kind != "PK":
            raise ValueError("send_ciphertext requires a PK message")

        def encapsulate() -> Message:
            # kyber-py follows the ML-KEM convention (shared_secret, ciphertext).
            shared_secret, ciphertext = ML_KEM_512.encaps(public_key_message.payload)
            self.party_b.shared_secret = shared_secret
            return Message("CT", ciphertext)

        return self._authorized("CT", encapsulate)

    def send_confirmation_a(self, ciphertext_message: Message) -> Message:
        """A decapsulates CT, then confirms possession of the shared secret."""
        if ciphertext_message.kind != "CT":
            raise ValueError("send_confirmation_a requires a CT message")

        def decapsulate_and_confirm() -> Message:
            if self.party_a.private_key is None:
                raise RuntimeError("A has no private key")
            self.party_a.shared_secret = ML_KEM_512.decaps(
                self.party_a.private_key, ciphertext_message.payload
            )
            return Message("CONF_A", _confirmation(self.party_a.shared_secret, b"CONF_A"))

        return self._authorized("CONF_A", decapsulate_and_confirm)

    def send_confirmation_b(self, confirmation_a: Message) -> Message:
        """B verifies A's confirmation and returns its own confirmation."""
        if confirmation_a.kind != "CONF_A":
            raise ValueError("send_confirmation_b requires a CONF_A message")

        def verify_and_confirm() -> Message:
            if self.party_b.shared_secret is None:
                raise RuntimeError("B has no shared secret")
            expected = _confirmation(self.party_b.shared_secret, b"CONF_A")
            if not hmac.compare_digest(confirmation_a.payload, expected):
                raise ValueError("CONF_A did not verify")
            return Message("CONF_B", _confirmation(self.party_b.shared_secret, b"CONF_B"))

        return self._authorized("CONF_B", verify_and_confirm)

    def replay_ciphertext(self, ciphertext_message: Message) -> bytes:
        """Attempt to process an already-seen CT (used only by the replay demo).

        The CT is classified and offered to the DFA *before* decapsulation.
        After an honest transcript the DFA is at ``established``, so this call
        raises DFARejection and the action below is never reached.
        """
        if ciphertext_message.kind != "CT":
            raise ValueError("replay_ciphertext requires a CT message")

        def decapsulate_replay() -> bytes:
            if self.party_a.private_key is None:
                raise RuntimeError("A has no private key")
            return ML_KEM_512.decaps(self.party_a.private_key, ciphertext_message.payload)

        return self._authorized("CT", decapsulate_replay)

    def run_honest_handshake(self) -> tuple[Message, Message, Message, Message]:
        """Run PK -> CT -> CONF_A -> CONF_B and assert shared-secret agreement."""
        pk = self.send_public_key()
        ct = self.send_ciphertext(pk)
        conf_a = self.send_confirmation_a(ct)
        conf_b = self.send_confirmation_b(conf_a)
        assert self.party_a.shared_secret == self.party_b.shared_secret
        assert self.dfa.accepted
        return pk, ct, conf_a, conf_b


def _confirmation(shared_secret: bytes, label: bytes) -> bytes:
    """A short HMAC confirmation, not a substitute for a complete protocol."""
    return hmac.new(shared_secret, label, sha256).digest()
