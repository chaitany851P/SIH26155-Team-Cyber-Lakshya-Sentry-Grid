#define SENTRY_EXPORTS
#include "sentry_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int sentry_extract_ipv4(const char *text, char ips_out[][32], int max_ips) {
    if (!text || max_ips <= 0) return 0;
    int count = 0;
    const char *p = text;

    while (*p && count < max_ips) {
        /* Find start of digits that isn't preceded by an alphanumeric */
        if (isdigit((unsigned char)*p) && (p == text || (!isalnum((unsigned char)*(p - 1)) && *(p - 1) != '.'))) {
            int octets[4];
            int chars_read = 0;
            if (sscanf(p, "%d.%d.%d.%d%n", &octets[0], &octets[1], &octets[2], &octets[3], &chars_read) == 4) {
                /* Validate valid octet ranges 0-255 */
                if (octets[0] >= 0 && octets[0] <= 255 &&
                    octets[1] >= 0 && octets[1] <= 255 &&
                    octets[2] >= 0 && octets[2] <= 255 &&
                    octets[3] >= 0 && octets[3] <= 255) {
                    
                    /* Verify character after IP is not alphanumeric or dot */
                    char next_ch = *(p + chars_read);
                    if (!isalnum((unsigned char)next_ch) && next_ch != '.') {
                        /* Check for duplicate */
                        char candidate[32];
                        snprintf(candidate, sizeof(candidate), "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
                        int duplicate = 0;
                        for (int k = 0; k < count; k++) {
                            if (strcmp(ips_out[k], candidate) == 0) {
                                duplicate = 1;
                                break;
                            }
                        }
                        if (!duplicate) {
                            strncpy(ips_out[count], candidate, 31);
                            ips_out[count][31] = '\0';
                            count++;
                        }
                        p += chars_read;
                        continue;
                    }
                }
            }
        }
        p++;
    }
    return count;
}

int sentry_extract_ports(const char *text, int ports_out[], int max_ports) {
    if (!text || max_ports <= 0) return 0;
    int count = 0;
    const char *keywords[] = {"port", "eq", "range", "transport", NULL};

    for (int k = 0; keywords[k] != NULL; k++) {
        const char *p = text;
        size_t kw_len = strlen(keywords[k]);
        while ((p = strstr(p, keywords[k])) != NULL && count < max_ports) {
            p += kw_len;
            while (*p == ' ' || *p == '\t') p++;
            int port_val = 0;
            if (isdigit((unsigned char)*p)) {
                port_val = atoi(p);
                if (port_val > 0 && port_val <= 65535) {
                    int dup = 0;
                    for (int j = 0; j < count; j++) {
                        if (ports_out[j] == port_val) { dup = 1; break; }
                    }
                    if (!dup) {
                        ports_out[count++] = port_val;
                    }
                }
            }
        }
    }
    return count;
}

int sentry_extract_ciphers(const char *text, char ciphers_out[][64], int max_ciphers) {
    if (!text || max_ciphers <= 0) return 0;
    int count = 0;
    static const char *known_ciphers[] = {
        "aes-256-gcm", "aes-128-gcm", "aes-256-cbc", "aes-128-cbc",
        "3des-cbc", "des-cbc", "chacha20-poly1305", "sha256", "sha512",
        "hmac-sha2-256", "hmac-sha2-512", "rsa-2048", "rsa-4096",
        "ecdsa-nistp256", "ecdsa-nistp384", "diffie-hellman-group14",
        "diffie-hellman-group16", NULL
    };

    /* Convert lower-case copy of text chunk or scan case-insensitively */
    for (int i = 0; known_ciphers[i] != NULL && count < max_ciphers; i++) {
        const char *needle = known_ciphers[i];
        size_t nlen = strlen(needle);
        const char *p = text;

        while (*p) {
            size_t j = 0;
            while (needle[j] && p[j] && (tolower((unsigned char)needle[j]) == tolower((unsigned char)p[j]))) {
                j++;
            }
            if (j == nlen) {
                /* Word boundary check */
                char prev = (p == text) ? ' ' : *(p - 1);
                char next = *(p + nlen);
                if (!isalnum((unsigned char)prev) && prev != '_' && !isalnum((unsigned char)next) && next != '_') {
                    strncpy(ciphers_out[count], needle, 63);
                    ciphers_out[count][63] = '\0';
                    count++;
                    break;
                }
            }
            p++;
        }
    }
    return count;
}
