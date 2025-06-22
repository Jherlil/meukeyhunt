#pragma once

struct str_tokenizer {
    char* str;
    char* next;
};

void stringtokenizer(char* str, str_tokenizer* tok);
char* nextToken(str_tokenizer* tok);
void freetokenizer(str_tokenizer* tok);
