#ifndef CUSTOMUTILH
#define CUSTOMUTILH

#ifdef __cplusplus
extern "C" {
#endif

typedef struct str_list {
    int n;
    char **data;
    int *lengths;
} List;

// Tokenizer nativo da biblioteca util.h
typedef struct str_tokenizer {
    char* str;
    char* next;
} str_tokenizer;

typedef struct {
    int current;
    int n;
    char **tokens;
} Tokenizer;

char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
char *trim(char *str, const char *seps);
int indexOf(char *s,const char **array,int length_array);

int hexchr2bin(char hex, char *out);
int hexs2bin(char *hex, unsigned char *out);
char *tohex(char *ptr,int length); // Esta função aloca memória, o chamador deve liberar.
void tohex_dst(char *ptr,int length,char *dst);

int hasMoreTokens(Tokenizer *t);
char *nextToken(Tokenizer *t);

int isValidHex(char *data);
void freetokenizer(Tokenizer *t);
void stringtokenizer(char *data,Tokenizer *t);

#ifdef __cplusplus
}
#endif

#endif // CUSTOMUTILH
