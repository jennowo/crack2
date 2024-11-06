#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find a matching hash in the hashFile.
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");
    if (!hashFile) {
        printf("Hash file could not be opened.\n");
        exit(1);
    }

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN];

    while(fgets(line, sizeof(line), hashFile) != NULL) {
        int length = strlen(line);

        // Trim newline
        if (length > 0 && line[length - 1] == '\n') {
            line[length - 1] = '\0';
        }
        
        // Attempt to match the hash from the file to the hash of the plaintext
        if(strcmp(hash, line) == 0) {           
            fclose(hashFile);
            return hash;                        // Return match
        }

    }

    // Close hashFile, free hash
    fclose(hashFile);
    free(hash);

    // No match found
    return NULL;
}


int main(int argc, char *argv[])
{
    int numCracked = 0;
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    char *hashName = argv[1];
    char *dictName = argv[2];

    // Open the dictionary file for reading.
    FILE *dictFile = fopen(dictName, "r");
    if(!dictFile) {
        printf("Dictionary file could not be opened");
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello

    char word[PASS_LEN];
    while (fgets(word, sizeof(word), dictFile)) {
        int length = strlen(word);

        // Remove newline
        if (length > 0 && word[length - 1] == '\n') {
            word[length - 1] = '\0';
        }

        char *hashMatch = tryWord(word, hashName);
        if(hashMatch) {
            printf("%s\t%s\n", hashMatch, word);
            numCracked++;
            free(hashMatch);
        }


    }
    
    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("Number of hashes cracked: %d\n", numCracked);
    
    // Free up any malloc'd memory?
    return 0;

}

