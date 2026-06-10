/**
 * Test: Buffer Overflow + Unsafe C String Operations.
 *
 * Expected detections:
 *   - CODE-013: Unsafe C string operation (strcpy, sprintf, gets)
 *   - CODE-015: Format-string vulnerability (printf with non-literal)
 *   - CODE-014: Non-constant-time secret comparison (strcmp on secret)
 *
 * This file simulates an embedded ECU firmware module that processes
 * CAN bus messages and has classic C memory-safety vulnerabilities.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_VIN_LEN 17
#define CMD_BUF_SIZE 64
#define AUTH_TOKEN "ECU_SECRET_9a8b7c6d5e4f"

/* CODE-013: strcpy with no bounds check — buffer overflow.
 * If `msg` exceeds CMD_BUF_SIZE, stack is smashed.
 */
void process_can_message(const char *msg) {
    char buffer[CMD_BUF_SIZE];
    strcpy(buffer, msg);  /* VULNERABLE: no length check */
    printf("Processing: %s\n", buffer);
}

/* CODE-013: sprintf with no bounds check.
 * `vin` could be longer than MAX_VIN_LEN, overflowing `formatted`.
 */
void format_vin_response(const char *vin, int status_code) {
    char formatted[128];
    sprintf(formatted, "VIN=%s STATUS=%d TIMESTAMP=%ld", vin, status_code, time(NULL));
    send_response(formatted);
}

/* CODE-015: Format-string vulnerability.
 * Attacker controls `user_msg` and can inject %x, %n to read/write memory.
 */
void log_diagnostic(const char *user_msg) {
    printf(user_msg);  /* VULNERABLE: should be printf("%s", user_msg) */
}

/* CODE-013: gets() — can never be used safely. */
void read_serial_command(void) {
    char input[256];
    printf("Enter command: ");
    gets(input);  /* VULNERABLE: no bounds, deprecated */
    execute_command(input);
}

/* CODE-014: Non-constant-time comparison of secret token.
 * Attacker can use timing side-channel to guess token byte-by-byte.
 */
int authenticate(const char *provided_token) {
    if (strcmp(provided_token, AUTH_TOKEN) == 0) {
        return 1;  /* authenticated */
    }
    return 0;
}

/* CODE-015: Another format-string — user controls the format. */
void display_error(const char *error_from_network) {
    char log_buf[512];
    sprintf(log_buf, error_from_network);  /* VULNERABLE */
    write_to_flash_log(log_buf);
}

/* Stubs */
void send_response(const char *resp) { /* send over CAN */ }
void execute_command(const char *cmd) { /* parse and run */ }
void write_to_flash_log(const char *msg) { /* persist */ }

int main(void) {
    process_can_message("DIAG_REQ:0x7E0:READ_DTC");
    format_vin_response("WBA12345678901234", 200);
    authenticate("user_supplied_token");
    return 0;
}
