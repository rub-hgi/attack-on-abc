/*
  This file is able to create the big DDTs (16 GiB each) used in the presented differential attacks.

Compile with:
  make / make arma
  or: g++ -O3 -std=c++11 -o armamatrix -larmadillo armamatrix.cpp

Usage : 
  ./armamatrix [-read <file>] [-read2 <file>] [-write <file>] [-m]

  -m : Multiply the DDTs. If set and both -read and -read2 are set, then those matrices will be
      multiplied. If only -read is set, then the given matrix will be squared.

      if not set, then the maximum index of the matrix given in -read will be calculated 
      (-read2 will be ignored)

  -read : Reads the matrix from the given file-path (if that file has correct formatting).
          If not set, then DDT1 will be calculated with the given 1-round-SBox of Byte2/4, 
          (which is much more inefficient).
  
  -read2: (Optional) if set, then a second matrix is read from the given file-path.
          Only used for multiplication, and only used if -read is set.
  
  -write: If set, then the Output-Matrix will be saved into the given file-path.
          if not, then nothing happens.


Example Usage: ./armamatrix -read DDT4 >> 4alpha49152



*/

#include <iostream>
#include <armadillo>
 

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;



void err_exit(const char* msg)
{
  perror(msg);
  exit(EXIT_FAILURE);
}

std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
std::chrono::steady_clock::time_point end;
void checkTime(void)
{
  end = std::chrono::steady_clock::now();
  std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << "[s]" << std::endl;
}





u16* byte2(int k) // k = 0
{
  u16 *arr = (u16*) malloc(0x10000*sizeof(u16));
  std::string path1 = "./keyrecovery/byte4_keyrecovery/";
  std::string path;
  char *string;
  char *token;

  path = path1 + std::to_string(k);
  FILE* file = fopen(path.c_str(),"rb");
  fseek(file, 0, SEEK_END);
  long fsize = ftell(file);
  string = (char*) malloc(fsize + 1);
  token = (char*) malloc(fsize + 1);
  fseek(file, 0, SEEK_SET);
  fread(string, fsize, 1, file);
  fclose(file);
  string[fsize] = 0;

  int i = 0;
  token = strtok(string,", ")+1;
  u16 result = 0;
  while (token)
  {
    result = strtoul(token, NULL, 10);
    arr[i] = result;
    i++;
    token = strtok(NULL,", ");
  }
  free(string);
  free(token);
  return arr;
}

u16* byte4(int k) // k = 0
{
  u16 *arr = (u16*) malloc(0x10000*sizeof(u16));
  std::string path1 = "./keyrecovery/byte4_keyrecovery/";
  std::string path;
  char *string;
  char *token;

  path = path1 + std::to_string(k);
  FILE* file = fopen(path.c_str(),"rb");
  fseek(file, 0, SEEK_END);
  long fsize = ftell(file);
  string = (char*) malloc(fsize + 1);
  token = (char*) malloc(fsize + 1);
  fseek(file, 0, SEEK_SET);
  fread(string, fsize, 1, file);
  fclose(file);
  string[fsize] = 0;

  int i = 0;
  token = strtok(string,", ")+1;
  u16 result = 0;
  while (token)
  {
    result = strtoul(token, NULL, 10);
    arr[i] = result;
    i++;
    token = strtok(NULL,", ");
  }
  free(string);
  free(token);
  return arr;
}

int main(int argc, char* argv[]) 
{

  //************ Check input **************//
  if (argc < 2)
  {
      err_exit("Usage: ./armamatrix <byte> [-read <file>] [-read2 <file>] [-write <file>] [-m] \n");
  }

  u8 byte = 0;
  bool multiply = false;
  bool read = false;
  bool read2 = false;
  bool write = false;
  char* path_readfile = NULL;
  char* path_readfile2 = NULL;
  char* path_writefile = NULL;
  
  char* end;
  byte = (u8) strtol(argv[1],&end,10);
  if(strlen(end) > 0) err_exit("strtol");
  if(byte != 2 && byte != 4) err_exit("Invalid byte inserted (only 2 or 4 allowed)");

  for (int arg = 1;arg<argc;arg++)
  {
      // Check input flags
      if (!strcmp(argv[arg],"-read"))
      {
      read = true;
      path_readfile = argv[arg+1];

      } 
      if (!strcmp(argv[arg],"-read2"))
      {
      read2 = true;
      path_readfile2 = argv[arg+1];
      } 
      if (!strcmp(argv[arg],"-write"))
      {
      write = true;
      path_writefile = argv[arg+1];
      } 
      if (!strcmp(argv[arg],"-m")) multiply = true;
  }
  

  if(read) printf("Read from: %s, %s\n",path_readfile, path_readfile2 );
  if(write) printf("Write to: %s\n",path_writefile);
  //***************************************//
  

  arma::Mat<float> DDT(0x10000,0x10000);
  arma::Mat<float> DDT2(0x10000,0x10000);

  if (read)
  {
      printf("Start reading:\n"); 
      if(DDT.load(path_readfile)) printf("matrix1 loaded.\n");
      else err_exit("matrix1 didnt load.\n");
      if(read2)
      {
          if(DDT2.load(path_readfile2)) printf("matrix2 loaded.\n");
          else err_exit("matrix2 didnt load.\n");
      }
      // load DDT from file
  }
  else
  {
      printf("Start calculating:\n");
      u16* S;
    
      if(byte == 4) S = byte4(0); 
      else if(byte == 2) S = byte2(0);
      else err_exit("Byteno. not allowed. Only 2 or 4");
    
      for(u32 x = 0; x < 65536; x++)
      {
        if ((x & 0x1FF) == 0) std::cout << "#" << std::flush;
        for(u32 y = 0; y < 65536; y++)
        {
          DDT(x^y,S[x]^S[y]) = DDT(x^y,S[x]^S[y])+1;
        }
      }
      printf("Scaling the DDT...\n");
      for(u32 x = 0; x < 65536; x++)
        for(u32 y = 0; y < 65536; y++)
          DDT(x,y) = DDT(x,y) / 65536;

      free(S);
      printf("\nFinished creating the DDT.\n");
      checkTime();
  }
  printf("Go :D\n");
  checkTime();
  arma::Mat<float> DDT_out(0x10000,0x10000);

  if(!multiply)
  {
  // //************ Scaling the matrix *****************//
  
  // adressing of matrix entries: 
  // alpha = DDT.index_max() % 65536
  // beta = DDT.index_max() / 65536
    
    DDT(0,0) = 0;
    std::cout << "Overall max: " << DDT.max() << " " <<DDT.index_max() << std::endl;

    // ****************BYTE2*********************** //
    // std::cout << DDT.row(57351) << std::endl; // alpha
    // std::cout << DDT.row(49344) << std::endl; // alpha
    // std::cout << DDT.row(49152) << std::endl; // alpha
    // std::cout << "DDT[49344][64] = " << DDT(49152,128) << std::endl;
    // std::cout << "DDT[49152][128] = " << DDT(49152,128) << std::endl;
    // std::cout << "DDT[32832][16512] = " << DDT(49152,128) << std::endl;
    // ******************************************** //
    // ****************BYTE4*********************** //
    // std::cout << DDT.row(960) << std::endl; // alpha 
    // std::cout << DDT.row(32771) << std::endl; // alpha 
    // std::cout << DDT.row(57351) << std::endl; // alpha 
    // std::cout << "DDT[960][64] = " << DDT(960,64) << std::endl;
    // std::cout << "DDT[32771][16394] = " << DDT(57351,16394) << std::endl;
    // std::cout << "DDT[57351][16394] = " << DDT(57351,16394) << std::endl;
    // ******************************************** //

    
  
    return EXIT_SUCCESS;
  
  }
  else
  {
    //************** Matrix multiplication **************//
    printf("Gonna multiply now. (Takes ages) \n");
    
    // DDT_out = DDT;
    
    if(read && read2) DDT_out = DDT * DDT2;
    else DDT_out = powmat(DDT,2);

    //***************************************************//

  
  }

  // Write DDT to file 
  if (write)
  {
      printf("Writing...\n");
      DDT_out.save(path_writefile);
      printf("Done writing.\n");
      printf("Close\n");
  }
  else
  {
      // std::cout << DDT_out << std::endl;
  }

  printf("Done :D\n");
  checkTime();

  return 0;
}
