/* Android command console adaptation; no GNU readline/ncurses runtime required.
 * Apache-2.0. Command parsing remains the unmodified official vpncmd implementation.
 * Input is line-based; host terminal editing/history shortcuts are not emulated.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

char *readline(const char *prompt) {
    char *line = NULL;
    size_t capacity = 0;
    if (prompt != NULL) { fputs(prompt, stdout); fflush(stdout); }
    ssize_t length = getline(&line, &capacity, stdin);
    if (length < 0) { free(line); return NULL; }
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';
    return line;
}
void add_history(const char *line) { (void)line; }
int getch(void) {
    struct termios before, raw;
    int changed = tcgetattr(STDIN_FILENO, &before) == 0;
    if (changed) {
        raw = before;
        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) changed = 0;
    }
    int value = getchar();
    if (changed) tcsetattr(STDIN_FILENO, TCSANOW, &before);
    return value;
}
