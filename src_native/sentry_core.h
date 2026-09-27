#pragma once
#ifndef SENTRY_CORE_H
#define SENTRY_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #ifdef SENTRY_EXPORTS
    #define SENTRY_API __declspec(dllexport)
  #else
    #define SENTRY_API __declspec(dllimport)
  #endif
#else
  #define SENTRY_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ==================== 1. CRYPTOGRAPHIC CORE (SHA-512 & MERKLE) ==================== */
SENTRY_API void sentry_sha512(const uint8_t *data, size_t len, uint8_t digest[64]);
SENTRY_API void sentry_sha512_hex(const uint8_t *data, size_t len, char hex_out[129]);
SENTRY_API int sentry_merkle_root(const char **leaf_hashes, size_t count, char root_out[129]);
SENTRY_API void sentry_block_seal(int64_t index, const char *prev_hash, const char *merkle_root, int64_t timestamp_ms, const char *validator, char seal_out[129]);

/* ==================== 2. VECTOR MATHEMATICS & NEURAL ROUTING ==================== */
SENTRY_API float sentry_vector_dot(const float *a, const float *b, int n);
SENTRY_API float sentry_vector_norm(const float *a, int n);
SENTRY_API float sentry_vector_cosine_similarity(const float *a, const float *b, int n);
SENTRY_API void sentry_vector_batch_cosine(const float *query, const float *matrix, int num_vectors, int dim, float *scores_out);
SENTRY_API void sentry_vector_softmax(float *vec, int n);

/* ==================== 3. CLI LEXER & FAST ENTITY EXTRACTION ==================== */
SENTRY_API int sentry_extract_ipv4(const char *text, char ips_out[][32], int max_ips);
SENTRY_API int sentry_extract_ports(const char *text, int ports_out[], int max_ports);
SENTRY_API int sentry_extract_ciphers(const char *text, char ciphers_out[][64], int max_ciphers);

/* ==================== 4. DETERMINISTIC 24-RULE COMPLIANCE ENGINE ==================== */
#define MAX_FINDINGS 32

typedef struct {
    char rule_id[32];
    char title[128];
    char severity[16];      /* CRITICAL, HIGH, MEDIUM, LOW */
    int passed;             /* 1 = PASS, 0 = FAIL */
    char found_value[160];
    char framework_ref[64];
    char mitre_technique[32];
} SentryFinding;

typedef struct {
    int total_rules;
    int passed_count;
    int failed_count;
    float overall_score;
    float disa_stig_score;
    float cis_score;
    float nist_score;
    float iso_score;
    SentryFinding findings[MAX_FINDINGS];
    char cryptographic_seal[129];
    double execution_time_us;
} SentryComplianceReport;

SENTRY_API int sentry_audit_configuration(const char *config_text, const char *vendor_hint, SentryComplianceReport *report);

/* Version info */
SENTRY_API const char* sentry_native_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SENTRY_CORE_H */
