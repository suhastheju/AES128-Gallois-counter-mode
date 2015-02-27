#ifndef AES128GCM_H
#define AES128GCM_H
//-------------------------------------------------------------------
// FILE: aes128gcm.c
// AUTHOR: Suhas Thejaswi
// DATE: 12-nov-2014
// MODIFIED: 12-nov-2014 //gmul initial version completed and tested
// DESCRIPTION:
//  This file is the header file of aes128gcm implementation
//-------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes128e.h"

void aes128gcm( unsigned char *ciphertext, 
                unsigned char *tag, 
                const unsigned char *k, 
                const unsigned char *IV, 
                const unsigned char *plaintext, 
                const unsigned long len_p, 
                const unsigned char* add_data, 
                const unsigned long len_ad
                );
//------------------------------------------------------------------
// DESCRIPTION:
//  implementation of aes128 Gllois counter mode function
//------------------------------------------------------------------

void gmul_128( const unsigned char *X,
               const unsigned char *Y, 
               unsigned char *out);
//------------------------------------------------------------------
// DESCRIPTION:
//  Gallois filed multiplicatoin under 128 bit
//  Algorithm is taken from RFC 
//  http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
//  page number 8
//------------------------------------------------------------------

void xor_128( const unsigned char *X, 
              const unsigned char *Y, 
              unsigned char *out
              );
//------------------------------------------------------------------
// DESCRIPTION:
//  xclusive or the two arrays which are 16 byte
//------------------------------------------------------------------

void gctr( const unsigned char *P, //plain text
           const unsigned char *key, //key for encryption
           const unsigned char *counter, //ICB
           const unsigned long len_p, //length of plain text
           unsigned char *output //output
           );
//------------------------------------------------------------------
// DESCRIPTION:
//  implementation of gallois counter mode function
//  Algorithm taken from document csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
//  page number 21
//------------------------------------------------------------------


void ghash_128( const unsigned char *H, 
                const unsigned char *X, 
                const unsigned int nblocks,
                unsigned char *out);
//------------------------------------------------------------------
// DESCRIPTION:
//  implementation of gallois counter mode function
//  Algorithm taken from document csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
// page number 20
//------------------------------------------------------------------

void inc_ctr(unsigned char *ctr);
//------------------------------------------------------------------
// DESCRIPTION:
//  increments the counter value by 1, counter is a 16 byte array
//  function also considers the moving of carry bit
//------------------------------------------------------------------

void long_to_carray( const unsigned long num, //input
                     unsigned char *output //output character array
                     );
//------------------------------------------------------------------
// DESCRIPTION:
//  converts long to character array of 8 bytes
//------------------------------------------------------------------
#endif
