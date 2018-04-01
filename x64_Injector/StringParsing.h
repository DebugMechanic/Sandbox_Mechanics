#ifndef STRINGPARSING_H
#define STRINGPARSING_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define MAXPREFIXTABLE 1024

#define ALPHABET_LEN 256
#define NOT_FOUND patlen
#define max(a, b) ((a < b) ? b : a)

int BruteForce_Search(char * pPattern, char *pText);

int KMP_Search(char *pPattern, char *pText);
void Build_PrefixTable(char *pPattern, int iPatternLen, int *iPrefixTable);

uint8_t* boyer_moore(uint8_t *string, uint32_t stringlen, uint8_t *pat, uint32_t patlen);
void make_delta2(int *delta2, uint8_t *pat, int32_t patlen);
int suffix_length(uint8_t *word, int wordlen, int pos);
int is_prefix(uint8_t *word, int wordlen, int pos);
void BadMatchTable(int *delta1, uint8_t *pat, int32_t patlen);



#endif








