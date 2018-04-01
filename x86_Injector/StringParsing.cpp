#include "StringParsing.h"



int BruteForce_Search(char * pPattern, char *pText)
{
	unsigned int i, j;
	int iPatLen  = strlen(pPattern); // Pattern Length 
	int iTextLen = strlen(pText);    // Text Length

	for (i = 0, j = 0; j < iPatLen && i < iTextLen; i++, j++)
	{
		while (pText[i] != pPattern[j] && i < iTextLen)
		{
			i -= j - 1;
			j = 0;
		}
	}

	if (j == iPatLen)
		return i - iPatLen; // Position of match returned.
	else
		return -1;           // no match.
}


// acacabacacabacacac
void Build_PrefixTable(char *pPattern, int iPatternLen, char *iPrefixTable)
{
	int i; // Pattern Index
	int j; // Set Prefix Table Value

	iPrefixTable[0] = 0;
	for (i = 1, j = 0; i < iPatternLen; i++)
	{
		// Is i not equal to j?
		// Is j equal to zero?
		while ((j > 0) && pPattern[i] != pPattern[j])
		{
			j = iPrefixTable[j - 1]; // Get
		}

		// Is i equal to j?
		if (pPattern[i] == pPattern[j]){
			iPrefixTable[i] = ++j; // Set
		}
		else{
			iPrefixTable[i] = j;   // Set
		}
	}
}


int KMP_Search(char *pPattern, char *pText)
{
	char iPrefixTable[MAXPREFIXTABLE];
	int i, k;
	int m = strlen(pPattern);
	int n = strlen(pText);

	memset(iPrefixTable, -1, MAXPREFIXTABLE);

	if (m >= MAXPREFIXTABLE)
		return 0;

	Build_PrefixTable(pPattern, m, iPrefixTable);

	for (i = 0, k = 0; i < n; i++)
	{
		while (k > 0 && pPattern[k] != pText[i])
		{
			k = iPrefixTable[k - 1];
		}

		if (pText[i] == pPattern[k]){
			k++;
		}

		if (k == m){
			// Found Pattern In Text
			printf("%d\n", i - m + 1);
			return (i - m + 1);
		}
	}

	// Pattern Not Found In Text...
	return 0;
}





/**************************************
*
* Boyer - Moore Algorithm, Begins Here
*
***************************************/


// Table must not contain repetitive characters
// This table will hold the number of skips
void BadMatchTable(int *delta1, uint8_t *pat, int32_t patlen)
{
	int i;
	for (i = 0; i < ALPHABET_LEN; i++)
	{
		delta1[i] = NOT_FOUND; // Uses Pattern Length as a filler.
	}

	for (i = 0; i < patlen - 1; i++)
	{
		delta1[pat[i]] = patlen - 1 - i; // Bad Match Table, Formula ( Value = length - index - 1 ).
		// For the last letter you keep the value equal to the length. This is for the wildcard characters in the text.
	}
 }


// true if the suffix of word starting from word[pos] is a prefix of word
int is_prefix(uint8_t *word, int wordlen, int pos) 
{
	int i;
	int suffixlen = wordlen - pos;

	// could also use the strncmp() library function here
	for (i = 0; i < suffixlen; i++) 
	{
		if (word[i] != word[pos + i]) 
		{
			return 0;
		}
	}
	return 1;
}


// length of the longest suffix of word ending on word[pos].
// suffix_length("dddbcabc", 8, 4) = 2
int suffix_length(uint8_t *word, int wordlen, int pos)
{
	int i;
	// increment suffix length i to the first mismatch or beginning of the word
	for ( i = 0; (word[pos - i] == word[wordlen - 1 - i]) && (i < pos); i++ );

	return i;
}


// delta2 table: 
// given a mismatch at pat[pos], we want to align with the next possible full match. 
// This could be based on what we know about pat[pos+1] to pat[patlen-1].
//
// In case 1:
// pat[pos+1] to pat[patlen-1] does not occur elsewhere in pat, the next plausible match starts at or after the mismatch.
// If, within the substring pat[pos+1 .. patlen-1], lies a prefix of pat, the next plausible match is here 
// (if there are multiple prefixes in the substring, pick the longest). 
// Otherwise, the next plausible match starts past the character aligned with pat[patlen-1].
// 
// In case 2:
// pat[pos+1] to pat[patlen-1] does occur elsewhere in pat. The mismatch tells us that we are not looking at the end of a match.
// We may, however, be looking at the middle of a match.
// 
// The first loop, which takes care of case 1, is analogous to the KMP table, adapted for a 'backwards' scan order with the
// additional restriction that the substrings it considers as potential prefixes are all suffixes. In the worst case scenario
// pat consists of the same letter repeated, so every suffix is a prefix. This loop alone is not sufficient, however:

// Suppose that pat is "ABYXCDBYX", and text is ".....ABYXCDEYX".
// We will match X, Y, and find B != E. There is no prefix of pat in the suffix "YX", so the first loop tells us to skip forward by 9 characters.
// Although superficially similar to the KMP table, the KMP table relies on information about the beginning of the partial match that the BM algorithm does not have.
//
// The second loop addresses case 2. Since suffix_length may not be unique, we want to take the minimum value, which will tell us
// how far away the closest potential match is.
void make_delta2(int *delta2, uint8_t *pat, int32_t patlen)
{
	int p; // First Loop: pattern length without \0
	int last_prefix_index = patlen - 1; // pattern length - \0

	// first loop
	for (p = patlen - 1; p >= 0; p--) // counts down from pattern length to zero
	{
		// is_prefix(uint8_t *word, int wordlen, int pos) 
		if (is_prefix(pat, patlen, p + 1)) // pos is right end
		{
			last_prefix_index = p + 1;
		}
		delta2[p] = last_prefix_index + (patlen - 1 - p);
	}

	// second loop
	for (p = 0; p < patlen - 1; p++) 
	{
		int slen = suffix_length(pat, patlen, p);
		if (pat[p - slen] != pat[patlen - 1 - slen]) 
		{
			delta2[patlen - 1 - slen] = patlen - 1 - p + slen;
		}
	}
}


uint8_t* boyer_moore(uint8_t *string, uint32_t stringlen, uint8_t *pat, uint32_t patlen)
{
	int i; // pattern length
	int delta1[ALPHABET_LEN];
	int *delta2 = (int *)malloc(patlen * sizeof(int));

	BadMatchTable(delta1, pat, patlen); // Pre-Process Pattern, Bad Character Table
	make_delta2(delta2, pat, patlen);

	// If pattern is empty
	if (patlen == 0) 
	{
		free(delta2);
		return string;
	}

	// Search For Pattern
	i = patlen - 1;
	while (i < stringlen) 
	{
		int j = patlen - 1;
		while ( j >= 0 && (string[i] == pat[j]) ) 
		{
			--i;
			--j;
		}

		if (j < 0) 
		{
			free(delta2);
			return (string + i + 1);
		}

		i += max( delta1[string[i]], delta2[j] );
	}

	free(delta2); // Free Allocated Memory
	return NULL;  // Not Found
}

