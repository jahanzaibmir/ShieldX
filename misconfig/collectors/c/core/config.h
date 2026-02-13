/**
 * config.h - Configuration management
 */

#ifndef SHIELDX_CONFIG_H
#define SHIELDX_CONFIG_H

typedef struct {
    int scan_timeout;
    int max_ports;
    int verbose;
} config_t;

int load_config(const char *filename, config_t *config);
void free_config(config_t *config);

#endif // SHIELDX_CONFIG_H