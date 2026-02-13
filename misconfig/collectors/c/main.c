/**
 * ShieldX Enhanced Collectors - Main Entry Point
 * Ultimate SOC-Grade Security Scanner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "core/logger.h"
#include "core/config.h"
#include "network/scanner.h"

// Global configuration
static config_t g_config;
static volatile int g_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    log_info("Received signal %d, shutting down gracefully...", signum);
    g_running = 0;
}

// Print usage information
void print_usage(const char *program_name) {
    printf("ShieldX Enhanced Security Collector v2.0\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -c, --config <file>     Configuration file path\n");
    printf("  -m, --module <name>     Run specific module (network|system|security|all)\n");
    printf("  -o, --output <file>     Output JSON file\n");
    printf("  -v, --verbose           Verbose logging\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Modules:\n");
    printf("  network     Network scanning and analysis\n");
    printf("  system      System configuration and processes\n");
    printf("  security    Vulnerability and compliance scanning\n");
    printf("  all         Run all modules (default)\n");
}

// Run network module
int run_network_module(FILE *output) {
    log_info("Starting network analysis module...");
    
    network_scan_result_t *results = scan_network(&g_config);
    if (!results) {
        log_error("Network scan failed");
        return -1;
    }
    
    // Output results as JSON
    fprintf(output, "{\n");
    fprintf(output, "  \"collector\": \"network\",\n");
    fprintf(output, "  \"timestamp\": %ld,\n", (long)time(NULL));
    
    // Output interfaces
    fprintf(output, "  \"interfaces\": [\n");
    for (int i = 0; i < results->interface_count; i++) {
        network_interface_t *iface = &results->interfaces[i];
        fprintf(output, "    {\n");
        fprintf(output, "      \"name\": \"%s\",\n", iface->name);
        fprintf(output, "      \"description\": \"%s\",\n", iface->description);
        fprintf(output, "      \"mac\": \"%s\",\n", iface->mac_address);
        fprintf(output, "      \"ipv4\": \"%s\",\n", iface->ipv4_address);
        fprintf(output, "      \"ipv6\": \"%s\",\n", iface->ipv6_address);
        fprintf(output, "      \"gateway\": \"%s\",\n", iface->gateway);
        fprintf(output, "      \"is_up\": %s,\n", iface->is_up ? "true" : "false");
        fprintf(output, "      \"is_wireless\": %s\n", iface->is_wireless ? "true" : "false");
        fprintf(output, "    }%s\n", (i < results->interface_count - 1) ? "," : "");
    }
    fprintf(output, "  ],\n");
    
    fprintf(output, "  \"findings\": [\n");
    for (size_t i = 0; i < results->finding_count; i++) {
        network_finding_t *f = &results->findings[i];
        fprintf(output, "    {\n");
        fprintf(output, "      \"type\": \"%s\",\n", f->type);
        fprintf(output, "      \"port\": %d,\n", f->port);
        fprintf(output, "      \"protocol\": \"%s\",\n", f->protocol);
        fprintf(output, "      \"service\": \"%s\",\n", f->service);
        fprintf(output, "      \"binding\": \"%s\",\n", f->binding);
        fprintf(output, "      \"state\": \"%s\",\n", f->state);
        fprintf(output, "      \"process\": \"%s\",\n", f->process_name);
        fprintf(output, "      \"pid\": %d,\n", f->pid);
        fprintf(output, "      \"risk_level\": \"%s\"\n", f->risk_level);
        fprintf(output, "    }%s\n", (i < results->finding_count - 1) ? "," : "");
    }
    
    fprintf(output, "  ],\n");
    fprintf(output, "  \"metadata\": {\n");
    fprintf(output, "    \"scan_duration_ms\": %d,\n", results->scan_duration_ms);
    fprintf(output, "    \"interfaces_found\": %d,\n", results->interface_count);
    fprintf(output, "    \"open_ports\": %d,\n", results->open_port_count);
    fprintf(output, "    \"active_connections\": %d,\n", results->connection_count);
    fprintf(output, "    \"firewall_enabled\": %s\n", results->firewall_enabled ? "true" : "false");
    fprintf(output, "  }\n");
    fprintf(output, "}\n");
    
    log_info("Network analysis completed: %zu findings", results->finding_count);
    free_network_results(results);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *config_file = "config.json";
    const char *output_file = NULL;
    const char *module = "network";
    int verbose = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) config_file = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--module") == 0) {
            if (i + 1 < argc) module = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Initialize logger
    log_init(verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO);
    log_info("ShieldX Enhanced Collector starting...");
    
    // Setup signal handlers
#ifdef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif
    
    // Load configuration
    if (load_config(config_file, &g_config) != 0) {
        log_warn("Failed to load configuration from %s, using defaults", config_file);
    }
    
    // Open output file
    FILE *output = stdout;
    if (output_file) {
        output = fopen(output_file, "w");
        if (!output) {
            log_error("Failed to open output file: %s", output_file);
            return 1;
        }
    }
    
    int result = 0;
    
    // Run requested module(s)
    if (strcmp(module, "network") == 0) {
        result = run_network_module(output);
    } else if (strcmp(module, "all") == 0) {
        result = run_network_module(output);
    } else {
        log_error("Unknown module: %s (only 'network' and 'all' supported currently)", module);
        print_usage(argv[0]);
        result = 1;
    }
    
    // Cleanup
    if (output != stdout) {
        fclose(output);
    }
    
    free_config(&g_config);
    log_cleanup();
    
    log_info("ShieldX Enhanced Collector finished (exit code: %d)", result);
    return result;
}