#ifndef AES128E_H
#define AES128E_H

//-------------------------------------------------------------------
// FILE: aes128e.h
// AUTHOR: Suhas Thejaswi
// DATE: 20-oct-2014
// MODIFIED: 27-oct-2014 //added encryption context structure
//           27-oct-2014 //added comments
// DESCRIPTION:
//-------------------------------------------------------------------

//definition of Encryption context structure
typedef struct 
{
  unsigned char state[4][4];//holds the state matrix
  unsigned char key[4][4];//holds key matrix
}enc_ctxt;


void aes128e(unsigned char *c, const unsigned char *p, 
              const unsigned char *k);
//-------------------------------------------------------------------
// DESCRIPTION:
//  Under the 16-byte key at k, encrypt the 16-byte plaintext at p 
//  and store it at c.
// PARAMENTERS:
//  c(OUT)- pointer to cipher text
//  p(IN)- pointer to plain text
//  k(IN)- pointer to key
//-------------------------------------------------------------------

void print_mat(unsigned char mat[][4]);
//-------------------------------------------------------------------
// DESCRIPTION:
//  prints the matrix, this function was used for debugging purpose
//  to check the values of the state matrix and key marix
// PARAMETERS:
//  mat(IN)- matrix to be printed
//-------------------------------------------------------------------

void subbytes(enc_ctxt *ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  function performs the affine substitution of sbox
// PARAMETERS:
//  ctxt(IN/OUT)- pointer to encryption context
//-------------------------------------------------------------------

void shiftrows(enc_ctxt *ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  performs shift rows functionality in the AES. first row is not
//  changed. second row is rotated once. third row twice and fourth
//  row is rotated thrice.
// PARAMETERS:
//  ctxt(IN/OUT)- pointer to encryption context
//-------------------------------------------------------------------

void mixcolumns(enc_ctxt * ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  state matrix is multiplied with the mix column matrix under 
//  gallois field multiplication. xtime(a) is multiply by 2 under
//  gallois field and xtime(a)^a is multiply by 3 in gallois field
// PARAMETERS:
//  ctxt(IN/OUT)- pointer to encryption context
//-------------------------------------------------------------------

void addroundkey(enc_ctxt *ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  state matrix is XOR with key martix. every element in state 
//  matrix is XORed with the corresponding element in key matrix
// PARAMETERS:
//  ctxt(IN/OUT)- pointer to encryption context
//-------------------------------------------------------------------

void init_mat(const unsigned char *cp,
               const unsigned char *k,
               enc_ctxt * ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  initialisation of the state matrix and key matrix from plain text
//  and key
// PARAMETERS:
//  cp(IN)- pointer to plain text
//  k(IN)- pointer to key 
//  ctxt(OUT)- pointer to encryption context
//-------------------------------------------------------------------

void keysched(unsigned int round, enc_ctxt *ctxt);
//-------------------------------------------------------------------
// DESCRIPTION:
//  this function implements the key scheduling algorithm of AES
// PARAMETERS:
//  round(IN)- indicates the number of round of encryption
//  ctxt(IN/OUT)- pointer to encryption context
//-------------------------------------------------------------------

#endif
