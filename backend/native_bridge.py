"""
SENTRY-GRID Native C11 Bridge
High-Performance C Acceleration for Cryptography, Vector Math, CLI Lexing, and 24-Rule Compliance.
Provides zero-overhead ctypes bindings to sentry_native.dll / libsentry_native.so with graceful Python fallbacks.
"""

import os
import sys
import ctypes
import hashlib
import math
from typing import List, Dict, Any, Optional

# Locate compiled native library
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN_DIR = os.path.join(_BASE_DIR, "bin")

_DLL_NAME = "sentry_native.dll" if sys.platform == "win32" else "libsentry_native.so"
_DLL_PATH = os.path.join(_BIN_DIR, _DLL_NAME)

_native_lib = None
_native_loaded = False
_native_version_str = "Python-Fallback (Native C not loaded)"


class SentryFinding(ctypes.Structure):
    _fields_ = [
        ("rule_id", ctypes.c_char * 32),
        ("title", ctypes.c_char * 128),
        ("severity", ctypes.c_char * 16),
        ("passed", ctypes.c_int),
        ("found_value", ctypes.c_char * 160),
        ("framework_ref", ctypes.c_char * 64),
        ("mitre_technique", ctypes.c_char * 32),
    ]


class SentryComplianceReport(ctypes.Structure):
    _fields_ = [
        ("total_rules", ctypes.c_int),
        ("passed_count", ctypes.c_int),
        ("failed_count", ctypes.c_int),
        ("overall_score", ctypes.c_float),
        ("disa_stig_score", ctypes.c_float),
        ("cis_score", ctypes.c_float),
        ("nist_score", ctypes.c_float),
        ("iso_score", ctypes.c_float),
        ("findings", SentryFinding * 32),
        ("cryptographic_seal", ctypes.c_char * 129),
        ("execution_time_us", ctypes.c_double),
    ]


def _init_native():
    global _native_lib, _native_loaded, _native_version_str
    if os.path.exists(_DLL_PATH):
        try:
            lib = ctypes.CDLL(_DLL_PATH)

            # 1. Version
            lib.sentry_native_version.restype = ctypes.c_char_p
            _native_version_str = lib.sentry_native_version().decode("utf-8")

            # 2. SHA-512 Hex
            lib.sentry_sha512_hex.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
            lib.sentry_sha512_hex.restype = None

            # 3. Merkle Root
            lib.sentry_merkle_root.argtypes = [
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.c_size_t,
                ctypes.c_char_p
            ]
            lib.sentry_merkle_root.restype = ctypes.c_int

            # 4. Block Seal
            lib.sentry_block_seal.argtypes = [
                ctypes.c_int64,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_int64,
                ctypes.c_char_p,
                ctypes.c_char_p
            ]
            lib.sentry_block_seal.restype = None

            # 5. Vector Math
            lib.sentry_vector_dot.argtypes = [
                ctypes.POINTER(ctypes.c_float),
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int
            ]
            lib.sentry_vector_dot.restype = ctypes.c_float

            lib.sentry_vector_norm.argtypes = [ctypes.POINTER(ctypes.c_float), ctypes.c_int]
            lib.sentry_vector_norm.restype = ctypes.c_float

            lib.sentry_vector_cosine_similarity.argtypes = [
                ctypes.POINTER(ctypes.c_float),
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int
            ]
            lib.sentry_vector_cosine_similarity.restype = ctypes.c_float

            lib.sentry_vector_batch_cosine.argtypes = [
                ctypes.POINTER(ctypes.c_float),
                ctypes.POINTER(ctypes.c_float),
                ctypes.c_int,
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_float)
            ]
            lib.sentry_vector_batch_cosine.restype = None

            # 6. Entity Extraction
            lib.sentry_extract_ipv4.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char * 32 * 64,
                ctypes.c_int
            ]
            lib.sentry_extract_ipv4.restype = ctypes.c_int

            lib.sentry_extract_ports.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_int
            ]
            lib.sentry_extract_ports.restype = ctypes.c_int

            # 7. Compliance Audit
            lib.sentry_audit_configuration.argtypes = [
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.POINTER(SentryComplianceReport)
            ]
            lib.sentry_audit_configuration.restype = ctypes.c_int

            _native_lib = lib
            _native_loaded = True
        except Exception as e:
            _native_loaded = False
            _native_version_str = f"Python-Fallback (Load error: {e})"


_init_native()


def is_native_available() -> bool:
    return _native_loaded


def get_native_engine_version() -> str:
    return _native_version_str


# ==================== CRYPTOGRAPHIC WRAPPERS ====================

def native_sha512_hex(data: bytes | str) -> str:
    """Computes FIPS 180-4 SHA-512 in native C with fallback to hashlib."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if _native_loaded and _native_lib:
        out_buf = ctypes.create_string_buffer(129)
        _native_lib.sentry_sha512_hex(data, len(data), out_buf)
        return out_buf.value.decode("ascii")
    return hashlib.sha512(data).hexdigest()


def native_merkle_root(leaf_hashes: List[str]) -> str:
    """Computes Merkle Tree root hash across an array of SHA-512 hashes in native C."""
    if not leaf_hashes:
        return native_sha512_hex(b"EMPTY_MERKLE_ROOT")
    if _native_loaded and _native_lib:
        arr_type = ctypes.c_char_p * len(leaf_hashes)
        c_leaves = arr_type(*[h.encode("ascii") for h in leaf_hashes])
        out_buf = ctypes.create_string_buffer(129)
        _native_lib.sentry_merkle_root(c_leaves, len(leaf_hashes), out_buf)
        return out_buf.value.decode("ascii")

    # Python fallback
    current = list(leaf_hashes)
    while len(current) > 1:
        next_lvl = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            combined = (left + right).encode("utf-8")
            next_lvl.append(hashlib.sha512(combined).hexdigest())
        current = next_lvl
    return current[0]


def native_block_seal(index: int, prev_hash: str, merkle_root: str, timestamp_ms: int, validator: str = "NTRO_VALIDATOR") -> str:
    """Computes sovereign block seal in native C."""
    if _native_loaded and _native_lib:
        out_buf = ctypes.create_string_buffer(129)
        _native_lib.sentry_block_seal(
            ctypes.c_int64(index),
            prev_hash.encode("ascii"),
            merkle_root.encode("ascii"),
            ctypes.c_int64(timestamp_ms),
            validator.encode("utf-8"),
            out_buf
        )
        return out_buf.value.decode("ascii")

    payload = f"{index}:{prev_hash}:{merkle_root}:{timestamp_ms}:{validator}".encode("utf-8")
    return hashlib.sha512(payload).hexdigest()


# ==================== VECTOR WRAPPERS ====================

def native_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Computes vector cosine similarity with SIMD/unrolled C loops."""
    n = len(vec_a)
    if n == 0 or len(vec_b) != n:
        return 0.0
    if _native_loaded and _native_lib:
        arr_a = (ctypes.c_float * n)(*vec_a)
        arr_b = (ctypes.c_float * n)(*vec_b)
        return float(_native_lib.sentry_vector_cosine_similarity(arr_a, arr_b, n))

    # Python fallback
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return max(-1.0, min(1.0, dot / (norm_a * norm_b)))


def native_batch_cosine(query: List[float], matrix: List[List[float]]) -> List[float]:
    """Computes batch cosine similarity across candidate vectors in native C."""
    num_vectors = len(matrix)
    if num_vectors == 0:
        return []
    dim = len(query)
    if _native_loaded and _native_lib:
        c_query = (ctypes.c_float * dim)(*query)
        flat_matrix = [val for row in matrix for val in row]
        c_matrix = (ctypes.c_float * len(flat_matrix))(*flat_matrix)
        c_scores = (ctypes.c_float * num_vectors)()
        _native_lib.sentry_vector_batch_cosine(c_query, c_matrix, num_vectors, dim, c_scores)
        return [float(c_scores[i]) for i in range(num_vectors)]

    return [native_cosine_similarity(query, row) for row in matrix]


# ==================== LEXER & ENTITY WRAPPERS ====================

def native_extract_entities(text: str) -> Dict[str, Any]:
    """Extracts IPv4 addresses, ports, and cryptographic ciphers using zero-allocation C scanning."""
    ips = []
    ports = []
    if _native_loaded and _native_lib:
        text_bytes = text.encode("utf-8", errors="ignore")
        # Extract IPs
        ip_arr = ((ctypes.c_char * 32) * 64)()
        ip_count = _native_lib.sentry_extract_ipv4(text_bytes, ip_arr, 64)
        for i in range(ip_count):
            ips.append(ip_arr[i].value.decode("ascii"))

        # Extract Ports
        port_arr = (ctypes.c_int * 64)()
        port_count = _native_lib.sentry_extract_ports(text_bytes, port_arr, 64)
        for i in range(port_count):
            ports.append(int(port_arr[i]))

        return {
            "ipv4_addresses": ips,
            "port_numbers": ports,
            "engine": "Native C11 Lexer"
        }

    # Python regex fallback
    import re
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    ports = [int(p) for p in re.findall(r'\b(?:port|eq)\s+([0-9]{1,5})\b', text)]
    return {
        "ipv4_addresses": list(dict.fromkeys(ips)),
        "port_numbers": list(dict.fromkeys(ports)),
        "engine": "Python Regex Fallback"
    }


# ==================== 24-RULE COMPLIANCE AUDIT WRAPPER ====================

def native_audit_configuration(config_text: str, vendor_hint: str = "Cisco") -> Dict[str, Any]:
    """Executes complete 24-rule deterministic compliance audit in native C in microseconds."""
    if _native_loaded and _native_lib:
        report = SentryComplianceReport()
        c_text = config_text.encode("utf-8", errors="ignore")
        c_vendor = vendor_hint.encode("utf-8", errors="ignore")
        ret = _native_lib.sentry_audit_configuration(c_text, c_vendor, ctypes.byref(report))
        if ret == 0:
            findings_list = []
            for i in range(report.total_rules):
                f = report.findings[i]
                findings_list.append({
                    "rule_id": f.rule_id.decode("utf-8", errors="ignore"),
                    "title": f.title.decode("utf-8", errors="ignore"),
                    "severity": f.severity.decode("utf-8", errors="ignore"),
                    "passed": bool(f.passed),
                    "status": "PASS" if f.passed else "FAIL",
                    "found_value": f.found_value.decode("utf-8", errors="ignore"),
                    "framework": f.framework_ref.decode("utf-8", errors="ignore"),
                    "mitre_technique": f.mitre_technique.decode("utf-8", errors="ignore"),
                })
            return {
                "native_accelerated": True,
                "engine": _native_version_str,
                "execution_time_us": round(report.execution_time_us, 2),
                "execution_time_ms": round(report.execution_time_us / 1000.0, 4),
                "total_rules": report.total_rules,
                "passed_count": report.passed_count,
                "failed_count": report.failed_count,
                "overall_score": round(report.overall_score, 2),
                "disa_stig_score": round(report.disa_stig_score, 2),
                "cis_score": round(report.cis_score, 2),
                "nist_score": round(report.nist_score, 2),
                "iso_score": round(report.iso_score, 2),
                "cryptographic_seal": report.cryptographic_seal.decode("ascii", errors="ignore"),
                "findings": findings_list
            }

    # Python Fallback
    return {
        "native_accelerated": False,
        "engine": "Python Fallback Engine",
        "error": "Native DLL not active"
    }
