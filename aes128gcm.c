//-------------------------------------------------------------------
// FILE: aes128gcm.c
// AUTHOR: Suhas Thejaswi
// DATE: 12-nov-2014
// MODIFIED: 12-nov-2014 //gmul initial version completed and tested
// DESCRIPTION:
//  This file is the implementation of the Galois counter mode for 
//  authentication
//-------------------------------------------------------------------

#include "aes128gcm.h"
#include<string.h>

//To enable log compile with -DENABLE_LOG option
#ifdef ENABLE_LOG
  #define LOG_ENABLED 0
  #define INFO_ENABLED 0
#else
  #define LOG_ENABLED 0
#endif

#define print_array(a, n) \
        if(INFO_ENABLED) \
        { \
          fprintf(stdout,"[INFO] %s ,%s:%d \n %s:" \
                  ,__FILE__, __FUNCTION__, __LINE__, #a); \
          for(int i=0;i<n;i++) \
            fprintf(stdout,"%02x ",a[i]); \
          fprintf(stdout,"\n"); \
        }

#define init_array(a, n) \
        for(int i=0;i<n;i++) \
          a[i]=0x00;

#define COPY_ARRAY(src, dst, n) \
        for(int i=0;i<n;i++) \
          dst[i]=src[i];

#define log_func_enter() \
        if(LOG_ENABLED) \
        { \
          fprintf( stdout, "[LOG] %s ,%s:%d enter\n" \
                    ,__FILE__,__FUNCTION__, __LINE__); \
        }

#define log_func_exit() \
        if(LOG_ENABLED) \
        { \
          fprintf( stdout, "[LOG] %s ,%s:%d exit\n" \
                    ,__FILE__,__FUNCTION__, __LINE__); \
        }

#define BLK_LEN 16
//------------------------------------------------------------------
void aes128gcm( unsigned char *ciphertext, //out
                unsigned char *tag, //out
                const unsigned char *k, 
                const unsigned char *IV, 
                const unsigned char *plaintext, 
                const unsigned long len_p, 
                const unsigned char* add_data, 
                const unsigned long len_ad) 
{
  log_func_enter();
  unsigned char counter_0[BLK_LEN];
  unsigned char A[BLK_LEN*len_ad];
  unsigned char P[BLK_LEN*len_p];
  unsigned char C[BLK_LEN*len_p];
  unsigned char empty[BLK_LEN];
  unsigned char H[BLK_LEN];

  unsigned long len_x=(len_p+len_ad+1);
  unsigned char X[BLK_LEN*len_x];
  unsigned char Y[BLK_LEN*len_x];
  unsigned char enc_counter[BLK_LEN];


  //init counter
  memcpy(counter_0, IV, 12);
  for(int i=12; i<15; i++)
    counter_0[i]=0x00;
  counter_0[15]= 0x01;

  memcpy(A, add_data, BLK_LEN*len_ad);
  memcpy(P, plaintext, BLK_LEN*len_p);
  init_array(C, BLK_LEN*len_p);

  gctr(P, k, counter_0, len_p, ciphertext);

  // initial value of H
  init_array(empty, BLK_LEN);
  aes128e(H, empty, k);

  memcpy(X, add_data, BLK_LEN*len_ad);
  memcpy(&X[BLK_LEN*(len_ad)], ciphertext, BLK_LEN*len_p);

  // getting the 8 byte version of length
  unsigned char len_ad_arr[8];
  unsigned char len_p_arr[8];
  long_to_carray(len_ad, len_ad_arr);
  long_to_carray(len_p, len_p_arr);

  //copy length
  memcpy(&X[BLK_LEN*(len_ad+len_p)], len_ad_arr, 8);
  memcpy(&X[BLK_LEN*(len_ad+len_p)+8], len_p_arr, 8);

  ghash_128(H, X, len_x, Y);
  aes128e(enc_counter, counter_0, k);

  xor_128(enc_counter, Y, tag);

  log_func_exit();
}

//------------------------------------------------------------------
void long_to_carray( const unsigned long num, 
                        unsigned char *output)
{
  log_func_enter();
  //Assuming: max size value of num as 2^32-1
  //mulitplication by 128 wont exceed the long range
  unsigned int endian=0x01;
  unsigned char *p=(unsigned char *)&endian;
  unsigned long l_num= num*128;
  if(*p==0x01)
  {
    //little endian
    p=(unsigned char *)&l_num;
    for(int i=sizeof(long)-1; i>=0; i--)
      output[i]= *(p++);
  }
  else
  {
    //big endian
    p=(unsigned char *)&l_num;
    for(int i=0; i<sizeof(long); i++)
      output[i]= *(p++);
  }

  log_func_exit();
}

//------------------------------------------------------------------
void gctr( const unsigned char *P, //plain text
           const unsigned char *key, //key for encryption
           const unsigned char *counter, //ICB
           const unsigned long len_p, //length of plain text
           unsigned char *output //output
           )
{
  log_func_enter();
  unsigned char ctr[BLK_LEN];
  unsigned char enc_ctr[BLK_LEN];
  if(len_p)
  {
    for(int i=0; i<BLK_LEN;i++)
      ctr[i]= counter[i];

    // encrypt and xor the counter
    for(int i=0; i<len_p; i++)
    {
      inc_ctr(ctr);
      aes128e(enc_ctr, ctr, key);
      xor_128( &P[i*BLK_LEN], enc_ctr, &output[i*BLK_LEN]);
    }
  }
  log_func_exit();
}

//------------------------------------------------------------------
void inc_ctr(unsigned char *ctr)
{
  log_func_enter();
  int carry_bit=1;
  for(int i=15;i>=12; i--)
  {
    if(ctr[i]==0xff && carry_bit==1)
    {   
      ctr[i]=0x00;
      carry_bit=1;
    }   
    else
    {   
      if(carry_bit == 1)
      {
        ctr[i]+=0x01;
        carry_bit=0;
      }
    }   
  }
  log_func_exit();
}

//------------------------------------------------------------------
void ghash_128(const unsigned char *H, 
               const unsigned char *X, 
               const unsigned int nblocks,
               unsigned char *out)
{
  log_func_enter();
  unsigned char Y[BLK_LEN];
  unsigned char xor[BLK_LEN];

  init_array(Y, BLK_LEN);
  init_array(xor, BLK_LEN);
  for(int i=0; i<nblocks; i++) //for all blocks
  { //Y=(X^Y)*H
    xor_128(Y, &X[i*BLK_LEN], xor);
    gmul_128(xor, H, Y);
  }

  memcpy(out, Y, BLK_LEN);
  log_func_exit();
}

//------------------------------------------------------------------
void gmul_128( const unsigned char* X, 
               const unsigned char* Y, 
               unsigned char *out)
{
  unsigned char V[BLK_LEN];
  unsigned char Z[BLK_LEN];
  const unsigned char R= 0xe1;

  init_array(Z, BLK_LEN);
  memcpy(V, X, BLK_LEN);

  for(int i=0;i<128;i++)
  {
    //if 0 bit is set
    if(Y[(i/8)] & (1 << (7-(i%8)))) 
    {
      for(int j=0;j<BLK_LEN;j++)
        Z[j]^=V[j];  
    }

    if( !(V[15] & 0x01))
    { //if 127 bit is 0
      for(int j=0;j<BLK_LEN;j++)
      { 
        if (j!=0) //right shift
          if (V[15-j] & 0x01)
            V[BLK_LEN-j] |= 0x80;  
        V[15-j]>>=1; 
      }

    }
    else
    { //if 127 bit is 1
      for(int j=0;j<BLK_LEN;j++)
      { 
        if (j!=0) //right shift
          if (V[15-j] & 0x01)
            V[BLK_LEN-j] |= 0x80;
        V[15-j]>>=1;
      }
      V[0]^=R; //xor with R
    }
  }

  memcpy(out, Z, BLK_LEN);
}

//------------------------------------------------------------------
void xor_128(const unsigned char *X, 
             const unsigned char *Y, 
             unsigned char *out)
{
  log_func_enter();
  for(int i=0;i<BLK_LEN;i++)
    out[i]=X[i]^Y[i];
  log_func_exit();
}
