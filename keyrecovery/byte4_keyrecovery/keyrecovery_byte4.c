/*
    This file attacks byte4:
    ------------------------
    It creates a random key as well as plaintext-ciphertext pairs with that key
    and aims to recover the key that was used. 

    usage: ./keyrecovery_byte4 [-v] [<LEN>]

    -v : activates verbose mode (which e.g. prints the scoreboard).
    LEN : number of plaintext-ciphertext-pairs used to attack the key. 
        The bigger LEN, the higher the success rate of the attack.


*/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/random.h>

#include "../../applecipher.h"
#include "byte4.h"


static u32 STANDARD_LEN = 210;
bool verbose = false;


double* getAlphaTable(char* alpha_table_path)
{ 
    /* 
        Reads the content of the file "<alpha_table_path>" and converts it to an array of double*

        alpha_table_path: path of file containing the alpha_table
    */

    FILE* alpha_file = fopen(alpha_table_path,"r");
    if(alpha_file == NULL) die("Alpha file didnt open.\n");

    double* alpha_table = calloc(65536,sizeof(double));
    if(alpha_table == NULL) die("alpha table couldnt be malloced.\n");
    
    int i = 0;
    char* line = malloc(27);
    if(line == NULL) die("malloc");
    char* x;
    if(line == NULL) die("line couldnt be malloced.\n");
    while(fgets(line,27,alpha_file))
    {
        double token1 = atof(strtok(line," "));
        alpha_table[i++] = token1;
        if(i > 65536) die("i overflowed!");
        while((x = strtok(NULL," ")))
        {
            alpha_table[i++] = atof(x);
            if(i > 65536) die("i overflowed!");
        }
    }

    if (ferror(alpha_file)) die("fgets didnt work.\n");
    if(fclose(alpha_file)) die("fclose didnt work");
    return alpha_table;
}

int compare_func(const void* a,const void* b)
{
    // compare function for qsort to sort according to the score (maximum score at the top)
    const double** ia = (const double**) a;
    const double** ib = (const double**) b;
    if(ia[0][1] > ib[0][1]) return -1;
    if(ia[0][1] < ib[0][1]) return 1;
    return 0;
}

u16* getk(u8 key_num,u16 **Ps,u16 **Cs,size_t LEN)
{
    /*
        recovers the last two roundkeys of byte4 with chosen plaintext-pairs.

        key_num: indicates which rounds we are attacking.
        Ps: Array of plaintext-pairs with input difference alpha.
        Cs: Array of encrypted Ps
        LEN: Number of plaintext-pairs
    
    */

    u16 alpha;
    double* alpha_table;
    bool break_all = false;
    if(key_num == 1)
    {
        /* 
            Bruteforce all keys and check if it results expected ciphertext. 
            If so, try again with more pairs until 1 candidate remains.
        */

        u16 *cands,keys[65536];
        cands = malloc(1*sizeof(u16));
        if(cands == NULL) die("cands malloc failed.\n");
        for(int i = 0;i<65536;i++) keys[i] = 0;

        size_t i = 0,j = 0,ctr = 0;
        for(int p = 0;p<10;p++)
        {
            for(int k_try = 0;k_try < 65536;k_try++)
            {
                if(byte4(Ps[p][0],k_try,2) == Cs[p][0] && byte4(Ps[p][1],k_try,2) == Cs[p][1])
                    keys[k_try] = 1;
                else if(keys[k_try] == 1) keys[k_try] = 0;
            }
            ctr = 0;
            for(int m = 0;m<65536;m++)
            {
                if(keys[m] > 0) 
                {
                    cands = realloc(cands,sizeof(u16)*(ctr+1));
                    if(cands == NULL) die("cands realloc failed.\n");
                    cands[ctr++] = m;
                }
            }
            if(ctr == 1) break; // if one candidate remains,
            // we (hopefully) have found the correct roundkey for rounds 1 and 2.
        }    
        return cands;
    }
    else if(key_num == 2) // Recover k_2 and k_3
    {
        alpha = 960;
        alpha_table = getAlphaTable("./2alpha960");   
    }
    else if(key_num == 3) // Recover k_4 and k_5
    {
        alpha = 32771;
        alpha_table = getAlphaTable("./4alpha32771");     
    }
    else if(key_num == 4) // Recover k_6 and k_7
    {
        alpha = 57351;
        alpha_table = getAlphaTable("./6alpha57351");
    }
    else die("Key_num must be between 1 and 4\n");

    if ((Ps[0][0] ^ Ps[0][1]) != alpha) die("Ps dont have correct alphas.\n");
    double p,w;
    u32 impossible = 0;
    u16 W0,W1;
    double* scoreboard = calloc(65536,sizeof(double));
    if(scoreboard == NULL) die("calloc of scoreboard didnt work.\n");
    for(int k_try = 0; k_try < 65536; k_try++)
    {
        for(int c = 0;c<LEN;c++)
        {
            //------------------All in one attack------------------//
            W0 = byte4_dec(Cs[c][0],k_try,2);
            W1 = byte4_dec(Cs[c][1],k_try,2);

            p = alpha_table[W0 ^ W1];

            w = log(p * 65536);

            if(p != 0)
            {
                scoreboard[k_try] += w;
            } 
            else
            {
                scoreboard[k_try] = log(0);
                impossible++;
                break;
            } 
        }
    }
    
    int count = 0;
    double** sorted_scoreboard = malloc((count)*sizeof(double*));
    if(sorted_scoreboard == NULL) die("sorted scoreboard didnt malloc.\n");

    for(int i = 0;i<65536;i++)
    {
        if(scoreboard[i] > 0)
        {
            sorted_scoreboard = realloc(sorted_scoreboard,(++count)*sizeof(double*));
            sorted_scoreboard[count-1] = malloc(2*sizeof(double));
            if(sorted_scoreboard[count-1] == NULL) die("malloc of sorted_scoreboard[i] didnt work.\n");
            
            sorted_scoreboard[count-1][0] = (double) i;
            sorted_scoreboard[count-1][1] = scoreboard[i];
        }
    }
    if(count == 0) 
    {
        if(verbose) printf("No keys in scoreboard.");
        return NULL;
    }

    qsort(sorted_scoreboard,count,sizeof(double*),compare_func);
    
    if(verbose) // Prints the scoreboard
    {
        printf("\n#~~~~~~~~~~~~~~~SCOREBOARD~k%x~~~~~~~~~~~~~~~~~#\n",key_num);
        for(int h = 0;h<(count<20 ? count : 20);h++)
            printf("#   %04x %f\n",(int) sorted_scoreboard[h][0],sorted_scoreboard[h][1]);
        
        printf("#~~~~~~~~~~~~~~~~~~~~ ... %d ~~~~~~~~~~~~~~~~~~~~#\n",count);
    }
    
    u16* result = malloc((1+count)*sizeof(u16));
    if(result == NULL) die("result couldnt be malloced\n");
    for(int i = 0;i<count;i++)
        result[i] = (u16) sorted_scoreboard[i][0];
    

    if(verbose) printf("Impossibles: %f percent \n",impossible/655.36);

    free(alpha_table);
    free(sorted_scoreboard);
    return result; 
}




u64 keyrecovery(u8 key_nr,u16 ***Ps,u16 ***Cs,size_t LEN,u64 currently_guessed_key)
{
    /*
        Recursively runs getk to recover the correct key k_B4.
        It starts by creating the scoreboard of (k_B4,6 , k_B4,7), uses the top key of that scoreboard to 
        decrypt the Cs, so that we can attack earlier rounds similarily with getk. If the top key is not the correct key,
        there will quickly be an empty scoreboard in the next iteration, which makes this function use the second-top key.

        This results in a recursive, tree-like behaviour of keyrecovery, until it gets "all the way" to the first round;
        In that case, this function returns (with the correct key).

        key_nr: the rounds which we are attacking (valid values: 1-4)
            1: Recovers (k_B4,0 , k_B4,1)
            2: Recovers (k_B4,2 , k_B4,3)
            3: Recovers (k_B4,4 , k_B4,5)
            4: Recovers (k_B4,6 , k_B4,7)
        Ps: Array of plaintext-pairs with input difference alpha.
        Cs: Array of encrypted Ps
        LEN: Number of plaintext-pairs
        currently_guessed_key: The assumed key to use to decrypt the ciphertexts in order for the next iteration
            (0 at the beginning)

    */
    if(verbose) printf("[%x] currently guessed key: %16llx \t",key_nr,currently_guessed_key);
    else
    {
        printf("[%x] currently guessed key: %16llx \r",key_nr,currently_guessed_key);
        fflush(stdout);
    }
    if(key_nr == 0) return currently_guessed_key; // We found an entire key-candidate 

    // ********************* RECOVER ROUNDKEYS ********************* //
    u16* key_candidates = getk(key_nr,Ps[key_nr],Cs[key_nr],LEN);
    if(verbose) printf("\n");
    if (key_candidates == NULL) return log(0);
    // ************************************************************* //
    u16 key_cand,nr = 0; 

    while((key_cand = key_candidates[nr++])) // Walk through scoreboard and try to continue attack
    {
        for(int r = 4;r>0;r--)
            for (int i = 0;i<LEN;i++)
            {
                Cs[r][i][0] = byte4_dec(Cs[r][i][0],key_cand,2);
                Cs[r][i][1] = byte4_dec(Cs[r][i][1],key_cand,2);
            }
        // ********************* RECURSION ********************* //
        u64 new_key =  keyrecovery(key_nr-1,Ps,Cs,LEN,currently_guessed_key | ((u64) key_cand <<16*(4-key_nr)));
        // ***************************************************** //
        if(new_key != log(0)) return new_key; // If next iteration yields empty scoreboard (wrong key assumed before)
        for(int r = 4;r>0;r--)
            for (int i = 0;i<LEN;i++)
            {
                Cs[r][i][0] = byte4(Cs[r][i][0],key_cand,2);
                Cs[r][i][1] = byte4(Cs[r][i][1],key_cand,2);
            }
    }
    if(verbose) printf("while loop ran all the way\n");
    return log(0); // We only reach this point if wrong key is used in earlier iterations
}


int main(int argc, char* argv[])
{
    u32 LEN;
    // ************** Check input ***************** //
    char* end;
    if(argc == 1) LEN = STANDARD_LEN;
    else if (argc >= 2 && argc <= 3)
        if(!strcmp(argv[1],"-v")) 
        {
            verbose = true;
            if(argc == 3) 
            {
                LEN = strtol(argv[2],&end,10);
                if(strlen(end) > 0) die("strtol");
            }
            else LEN = STANDARD_LEN;
        }
        else if(argc == 2)
        {
            LEN = strtol(argv[1],&end,10);
            if(strlen(end) > 0) die("strtol");
        }
        else die("usage: ./keyrecovery_byte4 [-v] [<LEN>]");
    else die("usage: ./keyrecovery_byte4 [-v] [<LEN>]");
    // ******************************************** //

    printf("No. of used pairs: %u\n",LEN);


    // **************Check if enc/dec works*********************** //
    u128 check_p = random_num() & 0xffff;
    u128 check_k = random_num() & 0xffffffffffffffff;
    if(byte4_dec(byte4(check_p,check_k,8),check_k,8) != check_p) die("byte4 dec/enc is not correct.\n");
    if(byte4(byte4_dec(check_p,check_k,8),check_k,8) != check_p) die("byte4 enc/dec is not correct.\n");
    // *********************************************************** //



    u16 alphas[5] = {0,0,960,32771,57351};
    

    
    u16 ***Ps,***Cs;

    Ps = malloc(5*sizeof(u16**));
    Cs = malloc(5*sizeof(u16**));
    for(int i = 0;i<5;i++)
    {
        Ps[i] = malloc(LEN*sizeof(u16*));
        Cs[i] = malloc(LEN*sizeof(u16*));
        for(int j = 0;j<LEN;j++)
        {
            Ps[i][j] = malloc(2*sizeof(u16));
            Cs[i][j] = malloc(2*sizeof(u16));
        }
    }
    
    u64 k = random_num() & 0xffffffffffffffff;
    if (verbose) printf("\n\n k: %llx\n",k);
    
    // Create the Ps and Cs 
    for(int r = 4;r>0;r--)
    {
        for (int i = 0;i<LEN;i++)
        {
            Ps[r][i][0] = random_num() & 0xffff;
            Ps[r][i][1] = Ps[r][i][0] ^ alphas[r];
            if(Ps[r][0] == Ps[r>0? r-1 : r+1][0]) die("Same vals for p. RNG not good\n");
            Cs[r][i][0] = byte4(Ps[r][i][0],k,8); 
            Cs[r][i][1] = byte4(Ps[r][i][1],k,8); 
        }
    }
    
    u64 guessed_key = keyrecovery(4,Ps,Cs,LEN,0);

    if(verbose)
    {
        printf("\n\n\n##############%s################\n#\n",k==guessed_key ? "RIGHT" : "WRONG");
        printf("#   Correct key: %llx\n",k);
        printf("#   Guessed key: %llx\n",guessed_key);
        printf("#\n###################################\n");
    }
    else 
    {
        printf("\t\t\t\t\t\t\t%s\n",k==guessed_key ? "correct" : "false");
    }
    
    

    for(int i = 0;i<5;i++)
    {
        for(int j = 0;j<LEN;j++)
        {
            free(Ps[i][j]);
            free(Cs[i][j]);
        }
        free(Ps[i]);
        free(Cs[i]);
    }
    free(Ps);
    free(Cs);

    return 0;
}

