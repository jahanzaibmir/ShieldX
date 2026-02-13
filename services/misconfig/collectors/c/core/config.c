/**
 * config.c - Configuration management implementation
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>

int load_config(const char *filename, config_t *config) {
    // Simple default config for now
    config->scan_timeout = 5000;
    config->max_ports = 65535;
    config->verbose = 0;
    return 0;
}

void free_config(config_t *config) {
    // Nothing to free for now
    (void)config;
}