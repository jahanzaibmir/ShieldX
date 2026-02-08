#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp;
    char buffer[4096];

    fp = _popen(
        "powershell -ExecutionPolicy Bypass -File "
        "\"C:\\ShieldX\\services\\misconfig\\probes\\windows\\ports.ps1\"",
        "r"
    );

    if (!fp) {
        fprintf(stderr, "Failed to run PowerShell probe\n");
        return 1;
    }

    printf("{\"raw_probe_output\":");

    printf("\"");
    while (fgets(buffer, sizeof(buffer), fp)) {
        for (char *p = buffer; *p; p++) {
            if (*p == '\"') printf("\\\"");
            else if (*p == '\n') printf("\\n");
            else printf("%c", *p);
        }
    }
    printf("\"}");

    _pclose(fp);
    return 0;
}
