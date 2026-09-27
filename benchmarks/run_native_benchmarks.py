"""
SENTRY-GRID Native C11 vs Pure Python Performance Benchmark
Measures execution latency, throughput, and acceleration speedup ratios across:
1. FIPS 180-4 SHA-512 Cryptographic Hashing
2. Hierarchical Merkle Tree Computation
3. 24-Rule Multi-Framework Compliance Audit
4. Dense Vector Cosine Similarity
5. Zero-Allocation CLI Lexer & Entity Extraction
"""

import sys
import os
import time
import hashlib
import json

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import native_bridge
from backend.server import evaluate_compliance, SAMPLES


def benchmark_sha512(iterations: int = 20000):
    payload = b"NTRO-DEFENSE-SOVEREIGN-AUDIT-SAMPLE-DATA-PACKET-2026-XCCDF-CNSA-2.0" * 8
    
    # 1. Native C
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = native_bridge.native_sha512_hex(payload)
    native_time = time.perf_counter() - t0
    native_ops = iterations / native_time

    # 2. Python hashlib
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = hashlib.sha512(payload).hexdigest()
    py_time = time.perf_counter() - t0
    py_ops = iterations / py_time

    return {
        "benchmark": "FIPS 180-4 SHA-512 Hashing",
        "iterations": iterations,
        "native_ops_per_sec": round(native_ops, 1),
        "python_ops_per_sec": round(py_ops, 1),
        "native_latency_us": round((native_time / iterations) * 1e6, 3),
        "python_latency_us": round((py_time / iterations) * 1e6, 3),
        "speedup_ratio": round(native_ops / max(1, py_ops), 2)
    }


def benchmark_merkle_tree(iterations: int = 5000):
    leaves = [hashlib.sha512(f"leaf-{i}".encode()).hexdigest() for i in range(16)]

    # 1. Native C
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = native_bridge.native_merkle_root(leaves)
    native_time = time.perf_counter() - t0
    native_ops = iterations / native_time

    # 2. Python loop
    def py_merkle(current):
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                l = current[i]
                r = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(hashlib.sha512((l + r).encode()).hexdigest())
            current = nxt
        return current[0]

    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = py_merkle(leaves)
    py_time = time.perf_counter() - t0
    py_ops = iterations / py_time

    return {
        "benchmark": "16-Leaf Merkle Tree Root Hash",
        "iterations": iterations,
        "native_ops_per_sec": round(native_ops, 1),
        "python_ops_per_sec": round(py_ops, 1),
        "native_latency_us": round((native_time / iterations) * 1e6, 3),
        "python_latency_us": round((py_time / iterations) * 1e6, 3),
        "speedup_ratio": round(native_ops / max(1, py_ops), 2)
    }


def benchmark_compliance_audit(iterations: int = 2000):
    sample_cfg = SAMPLES[0]["content"]

    # 1. Native C
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = native_bridge.native_audit_configuration(sample_cfg)
    native_time = time.perf_counter() - t0
    native_ops = iterations / native_time

    # 2. Python compliance engine (rules only)
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = evaluate_compliance(sample_cfg, "Cisco")
    py_time = time.perf_counter() - t0
    py_ops = iterations / py_time

    return {
        "benchmark": "24-Rule Deterministic Compliance Audit",
        "iterations": iterations,
        "native_ops_per_sec": round(native_ops, 1),
        "python_ops_per_sec": round(py_ops, 1),
        "native_latency_us": round((native_time / iterations) * 1e6, 3),
        "python_latency_us": round((py_time / iterations) * 1e6, 3),
        "speedup_ratio": round(native_ops / max(1, py_ops), 2)
    }


def benchmark_vector_cosine(iterations: int = 50000):
    vec_a = [0.1 * i for i in range(64)]
    vec_b = [0.05 * i for i in range(64)]

    # 1. Native C
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = native_bridge.native_cosine_similarity(vec_a, vec_b)
    native_time = time.perf_counter() - t0
    native_ops = iterations / native_time

    # 2. Python loop
    import math
    def py_cosine(a, b):
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb)

    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = py_cosine(vec_a, vec_b)
    py_time = time.perf_counter() - t0
    py_ops = iterations / py_time

    return {
        "benchmark": "64-Dim Vector Cosine Similarity",
        "iterations": iterations,
        "native_ops_per_sec": round(native_ops, 1),
        "python_ops_per_sec": round(py_ops, 1),
        "native_latency_us": round((native_time / iterations) * 1e6, 3),
        "python_latency_us": round((py_time / iterations) * 1e6, 3),
        "speedup_ratio": round(native_ops / max(1, py_ops), 2)
    }


def run_all_benchmarks():
    print("=" * 80)
    print("  SENTRY-GRID Native C11 vs Pure Python Performance Benchmarks")
    print(f"  Engine: {native_bridge.get_native_engine_version()}")
    print("=" * 80)

    results = [
        benchmark_sha512(),
        benchmark_merkle_tree(),
        benchmark_compliance_audit(),
        benchmark_vector_cosine()
    ]

    print("\n{:<38} | {:<12} | {:<12} | {:<10}".format(
        "Benchmark Function", "Native Latency", "Python Latency", "Speedup"
    ))
    print("-" * 80)
    for r in results:
        print("{:<38} | {:>9} µs | {:>9} µs | {:>7}x".format(
            r["benchmark"],
            r["native_latency_us"],
            r["python_latency_us"],
            r["speedup_ratio"]
        ))
    print("-" * 80)

    # Save to disk
    out_file = os.path.join(os.path.dirname(__file__), "native_benchmarks_report.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Detailed benchmark report saved to {out_file}\n")
    return results


if __name__ == "__main__":
    run_all_benchmarks()
