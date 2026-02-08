#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include "../include/zx_net_probe.h"

#define ALERT_THRESHOLD 15

int run_net_probe(void) {
    int suspicious_score = 0;

    // Simulated heuristics (real sensors expand this)
    suspicious_score += rand() % 10;     // port entropy
    suspicious_score += rand() % 8;      // fan-out behavior
    suspicious_score += rand() % 5;      // unusual IP class

    if (suspicious_score >= ALERT_THRESHOLD) {
        printf("{\"sensor\":\"net_probe\",\"score\":%d,\"verdict\":\"ANOMALOUS\"}\n",
               suspicious_score);
        return 1;
    }

    printf("{\"sensor\":\"net_probe\",\"score\":%d,\"verdict\":\"NORMAL\"}\n",
           suspicious_score);
    return 0;
}

int main(void) {
    srand((unsigned int)time(NULL));
    return run_net_probe();
}
