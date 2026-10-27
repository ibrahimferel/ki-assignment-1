"""Performance tests for app.crypto: time, speed and overhead.

What is measured, for AES-256-CBC, DES-CBC and RC4 (drop 1024):

* Time      : encryption and decryption time (median of several runs), for
              the bare cipher (ciphers.py) and for the full engine
              (engine.py: key generation + cipher + HMAC + key wrapping).
* Speed     : throughput in MB/s = plaintext size / time.
* Overhead  : - size overhead: extra bytes in the stored ciphertext
                (padding + HMAC tag) and the wrapped key, also as a percentage;
              - time overhead: engine time minus bare cipher time, i.e. the
                cost of key generation, HMAC and key wrapping.

Two ways to run it:

1. As tests (quick, small sizes), with the report printed:
       python -m pytest tests/test_crypto_performance.py -v -s

2. As a full benchmark (bigger sizes, more runs, CSV for the report):
       python tests/test_crypto_performance.py
       python tests/test_crypto_performance.py --sizes 1KB 1MB 10MB --runs 20 --csv hasil.csv

The tests only check things that hold on every computer (sizes, correctness,
positive times). Absolute speed depends on the CPU, so it is reported, not
asserted.
"""

import csv
import secrets
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

if __name__ == "__main__":  # allow "python tests/test_crypto_performance.py"
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app.crypto import ALGORITHMS, decrypt_copy, encrypt_one
from app.crypto import ciphers, engine, keys

# ----------------------------------------------------------------- settings

QUICK_SIZES = ["1KB", "64KB", "1MB"]
QUICK_RUNS = 5

FULL_SIZES = ["1KB", "16KB", "64KB", "256KB", "1MB", "5MB", "10MB"]
FULL_RUNS = 10

_UNITS = {"B": 1, "KB": 1024, "MB": 1024 * 1024}
_BLOCK = {"AES": 16, "DES": 8, "RC4": None}
_WRAP_HEADER = 1 + keys.NONCE_LENGTH + keys.TAG_LENGTH  # version + nonce + GCM tag


def parse_size(text: str) -> int:
    text = text.strip().upper()
    for unit in ("MB", "KB", "B"):
        if text.endswith(unit):
            return int(float(text[: -len(unit)]) * _UNITS[unit])
    return int(text)


def human_size(n: int) -> str:
    if n >= _UNITS["MB"] and n % _UNITS["MB"] == 0:
        return f"{n // _UNITS['MB']}MB"
    if n >= _UNITS["KB"] and n % _UNITS["KB"] == 0:
        return f"{n // _UNITS['KB']}KB"
    return f"{n}B"


def expected_padding(algorithm: str, size: int) -> int:
    """PKCS#7 always adds 1..block bytes; RC4 is a stream cipher, no padding."""
    block = _BLOCK[algorithm]
    return 0 if block is None else block - (size % block)


# ----------------------------------------------------------------- measuring

@dataclass
class Result:
    algorithm: str
    size: int
    runs: int
    # time, seconds (median)
    cipher_enc_s: float
    cipher_dec_s: float
    engine_enc_s: float
    engine_dec_s: float
    engine_reported_enc_s: float  # EncryptedCopy.encryption_time
    # speed, MB/s (bare cipher and full engine)
    cipher_enc_mbps: float
    cipher_dec_mbps: float
    engine_enc_mbps: float
    engine_dec_mbps: float
    # time overhead, seconds and percent (engine vs bare cipher)
    enc_time_overhead_s: float
    dec_time_overhead_s: float
    enc_time_overhead_pct: float
    dec_time_overhead_pct: float
    # size overhead, bytes
    ciphertext_size: int
    padding_bytes: int
    tag_bytes: int
    iv_bytes: int
    wrapped_key_bytes: int
    total_overhead_bytes: int
    total_overhead_pct: float


def _median_time(func, runs: int) -> float:
    func()  # warm-up run, not counted
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        func()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def _mbps(size: int, seconds: float) -> float:
    return (size / _UNITS["MB"]) / seconds if seconds > 0 else float("inf")


def _pct(part: float, whole: float) -> float:
    return 100.0 * part / whole if whole else 0.0


def measure(algorithm: str, size: int, runs: int, master_key: bytes) -> Result:
    plaintext = secrets.token_bytes(size)

    # 1. Bare cipher (ciphers.py) with a fixed key.
    key = keys.generate_key(algorithm)
    raw = ciphers.encrypt(algorithm, key, plaintext)
    assert ciphers.decrypt(algorithm, key, raw.ciphertext, raw.mode, raw.iv) == plaintext

    cipher_enc = _median_time(lambda: ciphers.encrypt(algorithm, key, plaintext), runs)
    cipher_dec = _median_time(
        lambda: ciphers.decrypt(algorithm, key, raw.ciphertext, raw.mode, raw.iv), runs
    )

    # 2. Full engine (engine.py): new key, cipher, HMAC, key wrapping.
    copy = encrypt_one(algorithm, master_key, plaintext)

    def _decrypt():
        return decrypt_copy(
            algorithm=copy.algorithm, mode=copy.mode, iv=copy.iv,
            wrapped_key=copy.wrapped_key, ciphertext=copy.ciphertext,
            master_key=master_key,
        )

    assert _decrypt() == plaintext

    reported = []

    def _encrypt():
        reported.append(encrypt_one(algorithm, master_key, plaintext).encryption_time)

    engine_enc = _median_time(_encrypt, runs)
    engine_dec = _median_time(_decrypt, runs)

    # 3. Size overhead of what is actually stored.
    padding = expected_padding(algorithm, size)
    iv_bytes = len(copy.iv) if copy.iv else 0
    total = (len(copy.ciphertext) - size) + iv_bytes + len(copy.wrapped_key)

    return Result(
        algorithm=algorithm,
        size=size,
        runs=runs,
        cipher_enc_s=cipher_enc,
        cipher_dec_s=cipher_dec,
        engine_enc_s=engine_enc,
        engine_dec_s=engine_dec,
        engine_reported_enc_s=statistics.median(reported[1:] or reported),
        cipher_enc_mbps=_mbps(size, cipher_enc),
        cipher_dec_mbps=_mbps(size, cipher_dec),
        engine_enc_mbps=_mbps(size, engine_enc),
        engine_dec_mbps=_mbps(size, engine_dec),
        enc_time_overhead_s=engine_enc - cipher_enc,
        dec_time_overhead_s=engine_dec - cipher_dec,
        enc_time_overhead_pct=_pct(engine_enc - cipher_enc, cipher_enc),
        dec_time_overhead_pct=_pct(engine_dec - cipher_dec, cipher_dec),
        ciphertext_size=len(copy.ciphertext),
        padding_bytes=padding,
        tag_bytes=engine.TAG_LENGTH,
        iv_bytes=iv_bytes,
        wrapped_key_bytes=len(copy.wrapped_key),
        total_overhead_bytes=total,
        total_overhead_pct=_pct(total, size),
    )


def run_benchmark(sizes, runs, master_key=None):
    master_key = master_key or secrets.token_bytes(keys.MASTER_KEY_LENGTH)
    return [measure(a, s, runs, master_key) for s in sizes for a in sorted(ALGORITHMS)]


# ----------------------------------------------------------------- reporting

def format_report(results) -> str:
    def ms(s):
        return f"{s * 1000:9.3f}"

    lines = [
        "",
        "=" * 100,
        "WAKTU & KECEPATAN (median; cipher = ciphers.py saja, engine = engine.py lengkap)",
        "=" * 100,
        f"{'Algo':<5}{'Ukuran':>8} | {'Enc ms':>9}{'Dec ms':>9}{'Enc MB/s':>10}{'Dec MB/s':>10}"
        f" | {'Eng enc ms':>11}{'Eng dec ms':>11}{'Enc MB/s':>10}{'Dec MB/s':>10}",
        "-" * 100,
    ]
    for r in results:
        lines.append(
            f"{r.algorithm:<5}{human_size(r.size):>8} |{ms(r.cipher_enc_s)}{ms(r.cipher_dec_s)}"
            f"{r.cipher_enc_mbps:10.1f}{r.cipher_dec_mbps:10.1f} |"
            f"{ms(r.engine_enc_s):>11}{ms(r.engine_dec_s):>11}"
            f"{r.engine_enc_mbps:10.1f}{r.engine_dec_mbps:10.1f}"
        )
    lines += [
        "",
        "OVERHEAD WAKTU (engine - cipher: generate key + HMAC-SHA256 + wrap/unwrap AES-GCM)",
        "-" * 100,
        f"{'Algo':<5}{'Ukuran':>8} | {'Enc +ms':>9}{'Enc +%':>9} | {'Dec +ms':>9}{'Dec +%':>9}",
    ]
    for r in results:
        lines.append(
            f"{r.algorithm:<5}{human_size(r.size):>8} |{ms(r.enc_time_overhead_s)}"
            f"{r.enc_time_overhead_pct:8.1f}% |{ms(r.dec_time_overhead_s)}"
            f"{r.dec_time_overhead_pct:8.1f}%"
        )
    lines += [
        "",
        "OVERHEAD UKURAN (byte tambahan yang disimpan per salinan)",
        "-" * 100,
        f"{'Algo':<5}{'Ukuran':>8} | {'Ciphertext':>11}{'Padding':>9}{'Tag':>6}{'IV':>5}"
        f"{'WrapKey':>9}{'Total':>8}{'Total %':>10}",
    ]
    for r in results:
        lines.append(
            f"{r.algorithm:<5}{human_size(r.size):>8} | {r.ciphertext_size:>11}{r.padding_bytes:>9}"
            f"{r.tag_bytes:>6}{r.iv_bytes:>5}{r.wrapped_key_bytes:>9}"
            f"{r.total_overhead_bytes:>8}{r.total_overhead_pct:>9.3f}%"
        )
    lines.append("=" * 100)
    return "\n".join(lines)


def write_csv(results, path) -> Path:
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    return path


# ----------------------------------------------------------------- pytest

@pytest.fixture(scope="module")
def results():
    return run_benchmark([parse_size(s) for s in QUICK_SIZES], QUICK_RUNS)


def _by(results, algorithm, size):
    return next(r for r in results if r.algorithm == algorithm and r.size == size)


def test_every_combination_is_measured(results):
    assert len(results) == len(ALGORITHMS) * len(QUICK_SIZES)


def test_times_are_positive(results):
    for r in results:
        for value in (r.cipher_enc_s, r.cipher_dec_s, r.engine_enc_s, r.engine_dec_s):
            assert value > 0, r


def test_engine_records_encryption_time(results):
    """EncryptedCopy.encryption_time (saved as encrypt_seconds) is filled in
    and is not larger than the whole encrypt_one call."""
    for r in results:
        assert r.engine_reported_enc_s > 0, r
        assert r.engine_reported_enc_s <= r.engine_enc_s * 1.5, r


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_padding_overhead_matches_pkcs7(algorithm):
    """Ciphertext = plaintext + padding + 32-byte HMAC tag."""
    master_key = secrets.token_bytes(keys.MASTER_KEY_LENGTH)
    for size in (0, 1, 7, 8, 15, 16, 17, 1000, 1024):
        copy = encrypt_one(algorithm, master_key, secrets.token_bytes(size))
        assert len(copy.ciphertext) == size + expected_padding(algorithm, size) + engine.TAG_LENGTH


@pytest.mark.parametrize("algorithm", sorted(ALGORITHMS))
def test_wrapped_key_size_is_constant(algorithm):
    """Wrapped key = version + nonce + GCM tag + (cipher key + MAC key)."""
    master_key = secrets.token_bytes(keys.MASTER_KEY_LENGTH)
    expected = _WRAP_HEADER + ciphers.key_len(algorithm) + engine.MAC_KEY_LENGTH
    for size in (0, 100, 10_000):
        copy = encrypt_one(algorithm, master_key, secrets.token_bytes(size))
        assert len(copy.wrapped_key) == expected


def test_iv_overhead(results):
    for r in results:
        assert r.iv_bytes == (_BLOCK[r.algorithm] or 0)


def test_relative_size_overhead_shrinks_with_bigger_files(results):
    """Overhead is a fixed number of bytes, so its percentage falls as files grow."""
    sizes = sorted({r.size for r in results})
    for algorithm in ALGORITHMS:
        pcts = [_by(results, algorithm, s).total_overhead_pct for s in sizes]
        assert pcts == sorted(pcts, reverse=True), (algorithm, pcts)
        assert pcts[-1] < 0.1  # under 0.1 % for 1 MB


def test_print_report(results):
    """Prints the tables. Use pytest -s to see them."""
    print(format_report(results))


# ----------------------------------------------------------------- script

def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark AES / DES / RC4 in app.crypto")
    parser.add_argument("--sizes", nargs="+", default=FULL_SIZES,
                        help="plaintext sizes, e.g. 1KB 64KB 1MB (default: %(default)s)")
    parser.add_argument("--runs", type=int, default=FULL_RUNS,
                        help="runs per measurement, median is reported (default: %(default)s)")
    parser.add_argument("--csv", default="crypto_benchmark.csv",
                        help="CSV output file (default: %(default)s)")
    args = parser.parse_args(argv)

    sizes = [parse_size(s) for s in args.sizes]
    print(f"Benchmark: {', '.join(human_size(s) for s in sizes)} x {args.runs} runs ...")
    results = run_benchmark(sizes, args.runs)
    print(format_report(results))
    print(f"CSV disimpan di: {write_csv(results, args.csv).resolve()}")


if __name__ == "__main__":
    main()
