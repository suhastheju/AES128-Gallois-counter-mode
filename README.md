# AES128-Gallois-counter-mode

AES Gallois counter mode Implementation
This code includes two parts
###1. Implementation of AES-128 block cipher
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
###2. Using AES-128 to implement Gallois authentication mode
  http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
  The length of the IV is fixed to 12 bytes (96 bits).
  The length of the plaintext is always a multiple of the block size (16 bytes). 
  The length of the associated data is also always a multiple of the block size (16 bytes).
  The lenght of the tag is one block (16 bytes). 

