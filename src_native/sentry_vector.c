#define SENTRY_EXPORTS
#include "sentry_core.h"
#include <math.h>
#include <stdlib.h>

float sentry_vector_dot(const float *a, const float *b, int n) {
    float sum0 = 0.0f, sum1 = 0.0f, sum2 = 0.0f, sum3 = 0.0f;
    int i = 0;
    /* 4-way loop unrolling for superscalar throughput */
    for (; i <= n - 4; i += 4) {
        sum0 += a[i + 0] * b[i + 0];
        sum1 += a[i + 1] * b[i + 1];
        sum2 += a[i + 2] * b[i + 2];
        sum3 += a[i + 3] * b[i + 3];
    }
    float total = (sum0 + sum1) + (sum2 + sum3);
    for (; i < n; i++) {
        total += a[i] * b[i];
    }
    return total;
}

float sentry_vector_norm(const float *a, int n) {
    float dot = sentry_vector_dot(a, a, n);
    return sqrtf(dot);
}

float sentry_vector_cosine_similarity(const float *a, const float *b, int n) {
    float norm_a = sentry_vector_norm(a, n);
    float norm_b = sentry_vector_norm(b, n);
    if (norm_a < 1e-9f || norm_b < 1e-9f) {
        return 0.0f;
    }
    float dot = sentry_vector_dot(a, b, n);
    float sim = dot / (norm_a * norm_b);
    if (sim > 1.0f) sim = 1.0f;
    if (sim < -1.0f) sim = -1.0f;
    return sim;
}

void sentry_vector_batch_cosine(const float *query, const float *matrix, int num_vectors, int dim, float *scores_out) {
    float query_norm = sentry_vector_norm(query, dim);
    if (query_norm < 1e-9f) {
        for (int i = 0; i < num_vectors; i++) scores_out[i] = 0.0f;
        return;
    }
    for (int i = 0; i < num_vectors; i++) {
        const float *row = matrix + (i * dim);
        float row_norm = sentry_vector_norm(row, dim);
        if (row_norm < 1e-9f) {
            scores_out[i] = 0.0f;
        } else {
            float dot = sentry_vector_dot(query, row, dim);
            float sim = dot / (query_norm * row_norm);
            if (sim > 1.0f) sim = 1.0f;
            if (sim < -1.0f) sim = -1.0f;
            scores_out[i] = sim;
        }
    }
}

void sentry_vector_softmax(float *vec, int n) {
    if (n <= 0) return;
    float max_val = vec[0];
    for (int i = 1; i < n; i++) {
        if (vec[i] > max_val) max_val = vec[i];
    }
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        vec[i] = expf(vec[i] - max_val);
        sum += vec[i];
    }
    if (sum > 1e-9f) {
        for (int i = 0; i < n; i++) {
            vec[i] /= sum;
        }
    }
}
