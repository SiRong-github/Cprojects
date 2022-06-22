/* 
crypto.c

Implementations for cryptography primatives and functions
  making use of them.

Skeleton written by Aidan Dang for COMP20007 Assignment 2 2022
  with Minor modifications by Grady Fitzpatrick
  implementation by <You>
*/
#include <crypto.h>
#include <sponge.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The sponge's rate, in bytes. This represents the maximum number of bytes
// which can be read from or written the start of the sponge's state before a
// permutation must occur.
#define RATE 16
// Delimiter byte value used after absorption of the message
#define DELIMITER_A 0xAD
// Delimiter byte used at the end of the last-used block
#define DELIMITER_B 0X77
// Number of RATE-sized blocks in crypto
#define CRYPTO_BLOCKS (CRYPTO_KEY_SIZE/RATE)

// Helpful min function that might be useful.
uint64_t min(uint64_t a, uint64_t b) { return a < b ? a : b; }

void hash(uint8_t *output, uint64_t output_len, uint8_t const *msg,
          uint64_t msg_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  /* variables */
  uint8_t msgBlocks = msg_len/RATE; //number of RATE-sized blocks in msg
  uint8_t r = msg_len%RATE; //remaining msg bytes
  uint8_t outputBlocks = output_len/RATE; //number of RATE-sized blocks in state
  uint8_t rOutput = output_len%RATE; //remaining state bytes
  
  /* absorption */
  sponge_write(&sponge, msg, min(msg_len, RATE), true);
  for(int i = 1; i < msgBlocks; i++) {
    sponge_permute(&sponge);
    sponge_write(&sponge, msg+i*RATE, RATE, true);       
  }
  sponge_permute(&sponge);
  sponge_write(&sponge, msg+(msgBlocks)*RATE, r, true); 

  /* demarcation */    
  sponge_demarcate(&sponge, r, DELIMITER_A);
  sponge_demarcate(&sponge, RATE-1, DELIMITER_B);

  /* squeezing */
  sponge_permute(&sponge);
  sponge_read(output, &sponge, min(output_len,RATE));  
  for(int i = 1; i < msgBlocks; i++){
    sponge_permute(&sponge);                 
    sponge_read(output+i*RATE, &sponge, RATE);  
  }
  sponge_permute(&sponge);   
  sponge_read(output+(outputBlocks)*RATE, &sponge, rOutput);    
       
  // Here are some examples of what sponge routines are called for various
  // invocations of this hash function:
  // hash(o, 5, m, 0) performs:
  //   sponge_write(&sponge, m, 0, true);
  //   sponge_demarcate(&sponge, 0, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, 5);
  //
  // hash(o, 16, m, 7) performs:
  //   sponge_write(&sponge, m, 7, true);
  //   sponge_demarcate(&sponge, 7, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, 16);
  //
  // hash(o, 23, m, 16) performs:
  //   sponge_write(&sponge, m, RATE, true);
  //   sponge_permute(&sponge);
  //   sponge_write(&sponge, m + RATE, 0, true);
  //   sponge_demarcate(&sponge, 0, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, RATE);
  //   sponge_permute(&sponge);
  //   sponge_read(o + RATE, &sponge, 7);
  //
  // hash(o, 32, m, 23) performs:
  //   sponge_write(&sponge, m, RATE, true);
  //   sponge_permute(&sponge);
  //   sponge_write(&sponge, m + RATE, 7, true);
  //   sponge_demarcate(&sponge, 7, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, RATE);
  //   sponge_permute(&sponge);
  //   sponge_read(o + RATE, &sponge, 16);
}

void mac(uint8_t *tag, uint64_t tag_len, uint8_t const *key, uint8_t const *msg,
         uint64_t msg_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the hash
  // function's, but should include a keying phase before the absorbing phase.
  // If you wish, you may also treat this as calculating the hash of the key
  // prepended to the message.

  /* variables */
  uint8_t msgBlocks = msg_len/RATE; //number of RATE-sized blocks in msg
  uint8_t r = msg_len%RATE; //remaining msg bytes
  uint8_t tagBlocks = tag_len/RATE; //number of RATE-sized blocks in tag
  uint8_t rTag = tag_len%RATE; //remaining tag bytes
  
  /* keying phase */
  for(int i = 0; i < CRYPTO_BLOCKS; i++) {
    sponge_write(&sponge, key+i*RATE, RATE, true);      
    sponge_permute(&sponge);
  }
  /* absorption */
  sponge_write(&sponge, msg, min(msg_len, RATE), true);
  for(int i = 1; i <= msgBlocks-1; i++) {
    sponge_permute(&sponge);
    sponge_write(&sponge, msg+i*RATE, RATE, true);       
  }
  sponge_permute(&sponge);
  sponge_write(&sponge, msg+(msgBlocks)*RATE, r, true);

  /* demarcation */    
  sponge_demarcate(&sponge, r, DELIMITER_A);
  sponge_demarcate(&sponge, RATE-1, DELIMITER_B);

  /* squeezing */
  sponge_permute(&sponge);
  sponge_read(tag, &sponge, min(tag_len,RATE));  
  for(int i = 1; i < tagBlocks; i++){
    sponge_permute(&sponge);      
    sponge_read(tag+i*RATE, &sponge, RATE);  
  }
  sponge_permute(&sponge);
  sponge_read(tag+(tagBlocks)*RATE, &sponge, rTag); 
}

void auth_encr(uint8_t *ciphertext, uint8_t *tag, uint64_t tag_len,
               uint8_t const *key, uint8_t const *plaintext,
               uint64_t text_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the mac function's,
  // but should after each write into the sponge's state, there should
  // immediately follow a read from the sponge's state of the same number of
  // bytes, into the ciphertext buffer.

  /* variables */
  uint8_t textBlocks = text_len/RATE; //number of RATE-sized blocks in text
  uint8_t r = text_len%RATE; //remaining text bytes
  uint8_t tagBlocks = tag_len/RATE; //number of RATE-sized blocks in tag
  uint8_t rTag = tag_len%RATE; //remaining tag bytes

  /* keying phase */
  for(int i = 0; i < CRYPTO_BLOCKS; i++) {
    sponge_write(&sponge, key+i*RATE, RATE, true);      
    sponge_permute(&sponge);
  }
  
  /* absorption */
  sponge_write(&sponge, plaintext, min(text_len, RATE), true);
  sponge_read(ciphertext, &sponge, min(text_len,RATE));  
  for(int i = 1; i < textBlocks; i++) {
    sponge_permute(&sponge);
    sponge_write(&sponge, plaintext+i*RATE, RATE, true);   
    sponge_read(ciphertext+i*RATE, &sponge, RATE);      
    sponge_write(&sponge, plaintext+(text_len)*RATE, r, true);    
  }
  sponge_permute(&sponge);
  sponge_write(&sponge, plaintext+(textBlocks)*RATE, r, true);    
  sponge_read(ciphertext+(textBlocks)*RATE, &sponge, r);  
  sponge_write(&sponge, plaintext+(text_len)*RATE, r, true);  

  /* demarcation */    
  sponge_demarcate(&sponge, r, DELIMITER_A);
  sponge_demarcate(&sponge, RATE-1, DELIMITER_B);

  /* squeezing */
  sponge_permute(&sponge);
  sponge_read(tag, &sponge, min(tag_len,RATE));  
  for(int i = 1; i < tagBlocks; i++){
    sponge_permute(&sponge);      
    sponge_read(tag+i*RATE, &sponge, RATE);  
  }
  sponge_permute(&sponge); 
  sponge_read(tag+(tagBlocks)*RATE, &sponge, rTag);
}

int auth_decr(uint8_t *plaintext, uint8_t const *key, uint8_t const *ciphertext,
              uint64_t text_len, uint8_t const *tag, uint64_t tag_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  // The implementation of this function is left as a challenge. It may assist
  // you to know that a ^ b ^ b = a. Remember to return 0 on success, and 1 on
  // failure.

  /* variables */
  uint8_t textBlocks = text_len/RATE; //number of RATE-sized blocks in text
  uint8_t r = text_len%RATE; //remaining text bytes
  uint8_t tagBlocks = tag_len/RATE; //number of RATE-sized blocks in tag
  uint8_t rTag = tag_len%RATE; //remaining tag bytes
  uint8_t other_tag[tag_len]; //output of squeezing phase to be used to check validity of authenticated tag

  /* keying phase */
  for(int i = 0; i < CRYPTO_BLOCKS; i++) {
    sponge_write(&sponge, key+i*RATE, RATE, true);      
    sponge_permute(&sponge);
  }

  /* absorption */
  sponge_write(&sponge, ciphertext, min(text_len, RATE), true); 
  sponge_read(plaintext, &sponge, min(text_len,RATE));  
  sponge_write(&sponge, ciphertext, min(text_len, RATE), false);
  for(int i = 1; i < textBlocks; i++) {
    sponge_permute(&sponge);
    sponge_write(&sponge, ciphertext+i*RATE, RATE, true);   
    sponge_read(plaintext+i*RATE, &sponge, RATE); 
    sponge_write(&sponge, ciphertext+i*RATE, RATE, false);         
  }
  sponge_permute(&sponge);
  sponge_write(&sponge, ciphertext+textBlocks*RATE, r, true); 
  sponge_read(plaintext+textBlocks*RATE, &sponge, r);    
  sponge_write(&sponge, ciphertext+(textBlocks)*RATE, r, false);   

  /* demarcation */    
  sponge_demarcate(&sponge, r, DELIMITER_A);
  sponge_demarcate(&sponge, RATE-1, DELIMITER_B);

  /* getting other tag through squeezing*/
  sponge_permute(&sponge);
  sponge_read(other_tag, &sponge, min(tag_len,RATE));  
  for(int i = 1; i < tagBlocks; i++){
    sponge_permute(&sponge);       
    sponge_read(other_tag+i*RATE, &sponge, RATE);  
  }
  sponge_permute(&sponge);      
  sponge_read(other_tag+(tagBlocks)*RATE, &sponge, rTag);   

  /* checking tag */
  for(int i = 0; i < tag_len; i++) {
    if(other_tag[i] != tag[i]) {
        return 1;
    }
  }
  return 0;
}
