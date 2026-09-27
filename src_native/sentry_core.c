#define SENTRY_EXPORTS
#include "sentry_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* sentry_native_version(void) {
    return "SENTRY-NATIVE-C11 v2.4.0 (MinGW-w64 / AVX-Ready / NTRO Sovereign Core)";
}

#ifdef SENTRY_CLI_APP
static void print_banner(void) {
    printf("================================================================================\n");
    printf("  SENTRY-GRID | Native C11 Sovereign Compliance Audit Core\n");
    printf("  %s\n", sentry_native_version());
    printf("================================================================================\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_banner();
        printf("Usage: %s <config_file_path> [--json] [--benchmark N]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s samples/cisco_ios_xe_sample.cfg\n", argv[0]);
        printf("  %s samples/cisco_ios_xe_sample.cfg --json\n", argv[0]);
        printf("  %s samples/cisco_ios_xe_sample.cfg --benchmark 1000\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];
    int json_mode = 0;
    int benchmark_runs = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_mode = 1;
        } else if (strcmp(argv[i], "--benchmark") == 0 && i + 1 < argc) {
            benchmark_runs = atoi(argv[++i]);
        }
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        fprintf(stderr, "Error: Unable to open file '%s'\n", filepath);
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = (char*)malloc(fsize + 1);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "Error: Memory allocation failed for file buffer (%ld bytes)\n", fsize);
        return 3;
    }

    size_t read_bytes = fread(buffer, 1, fsize, f);
    buffer[read_bytes] = '\0';
    fclose(f);

    if (benchmark_runs > 0) {
        print_banner();
        printf("[*] Running benchmark: %d iterations on '%s' (%ld bytes)...\n", benchmark_runs, filepath, fsize);
        SentryComplianceReport rep;
        double total_us = 0.0;
        for (int b = 0; b < benchmark_runs; b++) {
            sentry_audit_configuration(buffer, "Auto-Detect", &rep);
            total_us += rep.execution_time_us;
        }
        double avg_us = total_us / benchmark_runs;
        double ops_sec = 1000000.0 / avg_us;
        printf("[+] Benchmark Complete:\n");
        printf("    - Total Runs:      %d\n", benchmark_runs);
        printf("    - Mean Latency:    %.3f microseconds (%.4f ms)\n", avg_us, avg_us / 1000.0);
        printf("    - Audit Velocity:  %.1f configs/second\n", ops_sec);
        printf("    - Rules Evaluated: %d rules per pass\n", rep.total_rules);
        printf("    - Total Checks:    %ld evaluations\n\n", (long)benchmark_runs * rep.total_rules);
        free(buffer);
        return 0;
    }

    SentryComplianceReport report;
    sentry_audit_configuration(buffer, "Auto-Detect", &report);

    if (json_mode) {
        char clean_path[512];
        strncpy(clean_path, filepath, sizeof(clean_path) - 1);
        clean_path[sizeof(clean_path) - 1] = '\0';
        for (char *cp = clean_path; *cp; cp++) {
            if (*cp == '\\') *cp = '/';
        }
        printf("{\n");
        printf("  \"native_engine\": \"%s\",\n", sentry_native_version());
        printf("  \"file\": \"%s\",\n", clean_path);

        printf("  \"file_size_bytes\": %ld,\n", fsize);
        printf("  \"execution_time_us\": %.2f,\n", report.execution_time_us);
        printf("  \"overall_score\": %.2f,\n", report.overall_score);
        printf("  \"passed_count\": %d,\n", report.passed_count);
        printf("  \"failed_count\": %d,\n", report.failed_count);
        printf("  \"disa_stig_score\": %.2f,\n", report.disa_stig_score);
        printf("  \"cis_score\": %.2f,\n", report.cis_score);
        printf("  \"nist_score\": %.2f,\n", report.nist_score);
        printf("  \"iso_score\": %.2f,\n", report.iso_score);
        printf("  \"cryptographic_seal\": \"%s\",\n", report.cryptographic_seal);
        printf("  \"findings\": [\n");
        for (int i = 0; i < report.total_rules; i++) {
            SentryFinding *fn = &report.findings[i];
            printf("    {\n");
            printf("      \"rule_id\": \"%s\",\n", fn->rule_id);
            printf("      \"title\": \"%s\",\n", fn->title);
            printf("      \"severity\": \"%s\",\n", fn->severity);
            printf("      \"status\": \"%s\",\n", fn->passed ? "PASS" : "FAIL");
            printf("      \"found_value\": \"%s\",\n", fn->found_value);
            printf("      \"framework\": \"%s\",\n", fn->framework_ref);
            printf("      \"mitre_technique\": \"%s\"\n", fn->mitre_technique);
            printf("    }%s\n", (i == report.total_rules - 1) ? "" : ",");
        }
        printf("  ]\n");
        printf("}\n");
    } else {
        print_banner();
        printf("[+] Target File:        %s (%ld bytes)\n", filepath, fsize);
        printf("[+] Execution Latency:  %.2f microseconds (%.4f ms)\n", report.execution_time_us, report.execution_time_us / 1000.0);
        printf("[+] Compliance Score:   %.1f%%  [%d / %d PASSED]\n", report.overall_score, report.passed_count, report.total_rules);
        printf("[+] Framework Scores:   DISA STIG: %.1f%% | CIS: %.1f%% | NIST: %.1f%% | ISO: %.1f%%\n",
               report.disa_stig_score, report.cis_score, report.nist_score, report.iso_score);
        printf("[+] SHA-512 Seal:       %s\n\n", report.cryptographic_seal);

        printf("--------------------------------------------------------------------------------\n");
        printf("  RULE ID    | SEVERITY | STATUS | TITLE\n");
        printf("--------------------------------------------------------------------------------\n");
        for (int i = 0; i < report.total_rules; i++) {
            SentryFinding *fn = &report.findings[i];
            const char *color_status = fn->passed ? "PASS" : "FAIL";
            printf("  %-10s | %-8s | %-6s | %s\n", fn->rule_id, fn->severity, color_status, fn->title);
        }
        printf("--------------------------------------------------------------------------------\n");
    }

    free(buffer);
    return 0;
}
#endif
