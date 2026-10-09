"""Run the successful handshake, then demonstrate one rejected CT replay."""

from dfa_spec import DFARejection
from handshake import InProcessHandshake


def main() -> None:
    session = InProcessHandshake()
    _pk, ciphertext, _conf_a, _conf_b = session.run_honest_handshake()

    print("Honest handshake: PK -> CT -> CONF_A -> CONF_B")
    print(f"DFA accepting state: {session.dfa.state}")
    print("Shared-secret check: A and B agree")

    print("\nReplay attack: resend the already-used CT after establishment.")
    print(f"State before replay: {session.dfa.state}")
    print(f"Offending symbol: {ciphertext.kind}")
    try:
        session.replay_ciphertext(ciphertext)
    except DFARejection as error:
        print(f"REJECTED: {error}")
        print("No decapsulation was executed for the replayed ciphertext.")


if __name__ == "__main__":
    main()
