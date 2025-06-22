#include "stringutils.h"
#include <cstring>
#include <cstdlib>

void stringtokenizer(char* str, str_tokenizer* tok) {
    tok->str = strdup(str);
    tok->next = tok->str;
}

char* nextToken(str_tokenizer* tok) {
    if (!tok->next) return nullptr;

    char* start = tok->next;
    char* end = strchr(start, ' ');

    if (end) {
        *end = '\0';
        tok->next = end + 1;
    } else {
        tok->next = nullptr;
    }

    return start;
}

void freetokenizer(str_tokenizer* tok) {
    if (tok->str) free(tok->str);
    tok->str = nullptr;
    tok->next = nullptr;
}
