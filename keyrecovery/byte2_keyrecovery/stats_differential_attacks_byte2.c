/*
    This program is used to calculate the average rank (and % impossibles) of the standard 
    differential attack, the impossible differential attack and the all-in-one attack.

    This program loops over a range of pairs, to see how these stats behave with an increasing
    number of used pairs

    Compile with: make / make stats_differential_attacks_byte2
    Run with: ./stats_differential_attacks_byte2 [-all] [<min> <max> <step>]

    min: minimum number of plaintext-ciphertext-pairs used
    max: maximum number of plaintext-ciphertext-pairs used
    step: the step, how many more pairs are used in the next iteration
    -all: if set, the all-in-one approach is used to attack byte2. If not, the standard 
            differential attack is used    



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
#include "byte2.h"



static bool standard = true; // if standard == true, then standard differential cryptanalysis is performed, if false then all-in-one


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
    if (fclose(alpha_file)) die("fclose didnt work");
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

double* getk(u16 **Ps,u16 **Cs,size_t LEN,u64 real_key) 
{
    /*
        recovers the key with chosen plaintext-pairs.

        Ps: Array of plaintext-pairs with input difference alpha.
        Cs: Array of encrypted Ps
        LEN: Number of plaintext-pairs
        real_key: the correct key, used only for statistics (for example the average score of the correct key

    */

    double* alpha_table;
    bool break_all = false;
    
    u16 alpha = 0x8040; 
    u16 beta = 0x4080;
    alpha_table = getAlphaTable("./6alpha32832"); // ./6alpha32832 contains the DDT_6 for alpha = 32832 (= 0x8040) 

    if ((Ps[0][0] ^ Ps[0][1]) != alpha) die("Ps dont have correct alphas.\n");

    u32 impossible = 0;
    u16 W0,W1;
    double* scoreboard = calloc(65536,sizeof(double)); // scoreboard for all keys
    if(scoreboard == NULL) die("calloc of scoreboard didnt work.\n");

    double p,w;

    for(int k_try = 0; k_try < 65536; k_try++)
    {
        for(int c = 0; c < LEN;c++) 
        {
            if(!standard)
            {
                //------------------All in one attack------------------//
                W0 = byte2_dec(Cs[c][0],k_try,2);
                W1 = byte2_dec(Cs[c][1],k_try,2);

                p = alpha_table[W0 ^ W1];

                w = log(p * 65536);

                if(p != 0) 
                {
                    scoreboard[k_try] += w;
                } 
                else // Differential is impossible
                {
                    scoreboard[k_try] = log(0);
                    impossible++;
                    break;
                } 
            }   
            else 
            {
                //------------------standard diff attack---------------//
                W0 = byte2_dec(Cs[c][0],k_try,2);
                W1 = byte2_dec(Cs[c][1],k_try,2);
                if((W0 ^ W1) == beta) scoreboard[k_try] ++;
            }
        }
    }
    
    u32 count = 0;
    double** sorted_scoreboard = malloc((count)*sizeof(double*));
    if(sorted_scoreboard == NULL) die("sorted scoreboard didnt malloc.\n");

    for(int i = 0;i<65536;i++)
    {
        sorted_scoreboard = realloc(sorted_scoreboard,(++count)*sizeof(double*));
        sorted_scoreboard[count-1] = malloc(2*sizeof(double));
        if(sorted_scoreboard[count-1] == NULL) die("malloc of sorted_scoreboard[i] didnt work.\n");
        
        sorted_scoreboard[count-1][0] = (double) i;
        sorted_scoreboard[count-1][1] = scoreboard[i];

    }

    qsort(sorted_scoreboard,count,sizeof(double*),compare_func);


    double real_position = 0; // real_position : position of the correct key in scoreboard (used for statistics)
    while((sorted_scoreboard[(int) real_position][0] != (real_key & 0xffff)) && real_position < 65536)
        real_position++;


    free(alpha_table);
    free(scoreboard);


    double* stats = malloc(2*sizeof(double)); // stats contain the % of impossibles & the position of the correct key
    if(stats == NULL) die("malloc");

    stats[0] = impossible / 655.36;
    stats[1] = (double) (1+real_position);

    return (double*) stats; 
}




int main(int argc, char* argv[])
{
    // ***********************   Check input *********************** //
    if(argc > 2 && argc < 4) die("Usage: ./stats_DiffvsAi1_Byte2 [-all] [<min> <max> <step>]");
    if (argc >= 2 && !strcmp(argv[1],"-all"))
    {
        printf("All in one!\n");
        standard = false;
    }
    u16 min = 10,max = 50,step = 5;
    if((!standard && argc == 5) || (standard && argc == 4))
    {
        char* end;
        min = strtol(argv[1+(1-standard)],&end,10);
        if(strlen(end) > 0) die("strtol");
        max = strtol(argv[2+(1-standard)],&end,10);
        if(strlen(end) > 0) die("strtol");
        step = strtol(argv[3+(1-standard)],&end,10);
        if(strlen(end) > 0) die("strtol");
    }
    printf("No. of pairs: Min: %hu, Max: %hu, Step: %hu\n",min,max,step);
    // ************************************************************** //


    // **************Check if enc/dec works*********************** //
    u128 check_p = random_num() & 0xffff;
    u128 check_k = random_num() & 0xffffffffffffffff;
    if(byte2_dec(byte2(check_p,check_k,8),check_k,8) != check_p) die("byte2 dec/enc is not correct.\n");
    if(byte2(byte2_dec(check_p,check_k,8),check_k,8) != check_p) die("byte2 enc/dec is not correct.\n");
    // *********************************************************** //




    u16 alphas[5] = {0,0,49344,49152,32832};
    double avg_impossibles,avg_score;

    int TRIES = 200; // for each number of pairs, TRIES runs are run to compute the average score etc.
    u32 LEN; 

    for(LEN = min;LEN<=max;LEN+=step)
    {
        printf("Used number of pairs: %u\n",LEN);
        for(int try = 0;try < TRIES;try++)
        {
            u64 k = random_num() & 0xffffffffffffffff;
            
            u16 ***Ps,***Cs; // Ps : given plaintexts. Cs : encrypted Ps

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
            
            // Create the Ps and Cs 
            for(int r = 4;r>0;r--)
            {
                for (int i = 0;i<LEN;i++)
                {
                    Ps[r][i][0] = random_num() & 0xffff;
                    Ps[r][i][1] = Ps[r][i][0] ^ alphas[r];
                    Cs[r][i][0] = byte2(Ps[r][i][0],k,8); 
                    Cs[r][i][1] = byte2(Ps[r][i][1],k,8); 
                }
            }

            double* result = getk(Ps[4],Cs[4],LEN,k);

            avg_impossibles += result[0];
            avg_score += result[1];
        }
        avg_impossibles /= ((double) TRIES);
        avg_score /= (double) TRIES;

        printf("Average impossibles: (%u,%f)\n",LEN,avg_impossibles/100);
        printf("Average Score: (%u,%f)\n",LEN,avg_score);
    }
    return EXIT_SUCCESS;

}

