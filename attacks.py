import contextlib
import io
import multiprocessing
import os
import queue
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True

from handshake import HOST, PORT, recv_msg, run_client, send_msg, serve

# Every row checks the state and outcome, not just whether a socket closed.
CASES = [
    ("baseline", "PK CT CONF_A CONF_B", "established", "ESTABLISHED", "MAC"),
    ("replay", "honest; replay CONF_A", "established", "DFA_REJECT", "DFA"),
    ("replay", "recorded CONF_A first", "init", "DFA_REJECT", "DFA"),
    ("reorder", "CT first", "init", "DFA_REJECT", "DFA"),
    ("reorder", "CONF_A first", "init", "DFA_REJECT", "DFA"),
    ("downgrade", "PK CT; send CONF_B", "ciphertext-received", "DFA_REJECT", "DFA"),
    ("downgrade", "legacy tag 0x00", "init", "DFA_REJECT", "classification"),
    ("injection", "PK with 100 bytes", "init", "DFA_REJECT", "classification"),
    ("injection", "PK CT; send PK", "ciphertext-received", "DFA_REJECT", "DFA"),
    ("truncation", "PK CT; close", "ciphertext-received", "INCOMPLETE", "session end"),
    ("truncation", "PK header 800; send 100", "init", "INCOMPLETE", "session end"),
    ("content (limit)", "PK CT; random CONF_A", "confirmed", "MAC_FAIL", "MAC"),
    ("content (limit)", "recorded PK + CONF_A", "confirmed", "MAC_FAIL", "MAC"),
]


def _serve_quietly(results):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            serve(PORT, results)
    except OSError as error:
        sys.exit(f"Attack server failed: {error}")


def _wait_for_server(process, results):
    deadline = time.monotonic() + 5
    while process.is_alive() and time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.1):
                pass
            # The readiness probe is a real, incomplete session of its own.
            if results.get(timeout=3) != ("init", "EOF/timeout", "INCOMPLETE"):
                raise RuntimeError("Unexpected readiness outcome")
            return
        except ConnectionRefusedError:
            time.sleep(0.02)
    raise RuntimeError("Attack server did not start; check whether port 5050 is in use")


def _attack(sock, number, recorded):
    if number in (1, 2):
        with contextlib.redirect_stdout(io.StringIO()):
            secret, transcript = run_client(sock)
        if len(secret) != 32 or [symbol for symbol, _ in transcript] != [
            "PK", "CT", "CONF_A", "CONF_B"
        ]:
            raise RuntimeError("Honest handshake did not complete")
        if number == 2:
            send_msg(sock, "CONF_A", dict(transcript)["CONF_A"])
        return dict(transcript)
    if number in (3, 5):
        send_msg(sock, "CONF_A", recorded["CONF_A"])
    elif number == 4:
        send_msg(sock, "CT", recorded["CT"])
    elif number == 7:
        sock.sendall(struct.pack("!BH", 0, 0))
    elif number == 8:
        send_msg(sock, "PK", b"x" * 100)
    elif number == 11:
        sock.sendall(struct.pack("!BH", 1, 800) + b"x" * 100)
    else:
        send_msg(sock, "PK", recorded["PK"])
        tag, ciphertext = recv_msg(sock)
        if tag != 2 or len(ciphertext) != 768:
            raise RuntimeError("Server did not send a valid CT")
        if number == 6:
            send_msg(sock, "CONF_B", recorded["CONF_B"])
        elif number == 9:
            send_msg(sock, "PK", recorded["PK"])
        elif number == 12:
            send_msg(sock, "CONF_A", os.urandom(32))
        elif number == 13:
            send_msg(sock, "CONF_A", recorded["CONF_A"])
        # Case 10 closes immediately after receiving CT.
    return recorded


def main():
    results = multiprocessing.Queue()
    process = multiprocessing.Process(target=_serve_quietly, args=(results,), daemon=True)
    rows, recorded, failures = [], {}, []
    try:
        process.start()
        _wait_for_server(process, results)
        for number, case in enumerate(CASES, 1):
            attack, trace, expected_state, expected_outcome, stopped_by = case
            error = ""
            try:
                with socket.create_connection((HOST, PORT), timeout=2) as sock:
                    recorded = _attack(sock, number, recorded)
            except (OSError, ValueError, RuntimeError) as problem:
                error = str(problem)
            state, symbol, outcome = results.get(timeout=5)
            passed = not error and (state, outcome) == (expected_state, expected_outcome)
            rows.append((number, attack, trace, state, outcome, stopped_by, passed))
            if not passed:
                failures.append(f"Row {number}: expected {expected_state}/{expected_outcome}; "
                                f"got {state}/{symbol}/{outcome}. {error}")
    finally:
        if process.pid is not None:
            process.terminate()
            process.join(timeout=3)
        results.close()
        results.join_thread()

    print(f"{'#':<3} {'Attack':<15} {'Trace':<24} {'Server state at stop':<21} "
          f"{'Outcome':<12} {'Stopped by':<15} Result")
    for number, attack, trace, state, outcome, stopped_by, passed in rows:
        print(f"{number:<3} {attack:<15} {trace:<24} {state:<21} "
              f"{outcome:<12} {stopped_by:<15} {'PASS' if passed else 'FAIL'}")
    for failure in failures:
        print(failure)
    print("Baseline: matching secrets confirmed by verified CONF_B; no attack was stopped.")
    print("Classification maps malformed frames to INVALID; the DFA rejects INVALID.")
    print(f"{sum(row[-1] for row in rows)}/13 as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, queue.Empty) as error:
        reason = str(error) or "no server outcome; check that port 5050 is free"
        sys.exit(f"Evaluation failed: {reason}")
