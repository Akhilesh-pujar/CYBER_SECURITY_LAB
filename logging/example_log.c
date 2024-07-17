#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main() {
    // Open connection to syslog
    openlog("CProgram", LOG_PID | LOG_CONS, LOG_LOCAL0);

    // Log some messages
    syslog(LOG_INFO, "This is an informational message.");
    syslog(LOG_WARNING, "This is a warning message.");
    syslog(LOG_ERR, "This is an error message.");

    // Close connection to syslog
    closelog();

    return 0;
}
