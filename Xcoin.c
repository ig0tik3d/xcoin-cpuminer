#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "sph_luffa.h"
#include "sph_cubehash.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_echo.h"

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context 	blake1;
	sph_bmw512_context		bmw1;
	sph_groestl512_context	groestl1;
	sph_skein512_context	skein1;
	sph_jh512_context		jh1;
	sph_keccak512_context	keccak1;
	sph_luffa512_context 	luffa1;
	sph_cubehash512_context cubehash1;
	sph_shavite512_context  shavite1;
	sph_simd512_context		simd1;
	sph_echo512_context		echo1;
} Xhash_context_holder;

Xhash_context_holder base_contexts;

void init_Xhash_contexts()
{
    sph_blake512_init(&base_contexts.blake1);	
    sph_bmw512_init(&base_contexts.bmw1);	
    sph_groestl512_init(&base_contexts.groestl1);	
    sph_skein512_init(&base_contexts.skein1);	
    sph_jh512_init(&base_contexts.jh1);		
    sph_keccak512_init(&base_contexts.keccak1);	
    sph_luffa512_init(&base_contexts.luffa1);
    sph_cubehash512_init(&base_contexts.cubehash1);
    sph_shavite512_init(&base_contexts.shavite1);
    sph_simd512_init(&base_contexts.simd1);
    sph_echo512_init(&base_contexts.echo1);
}

static void Xhash(void *state, const void *input)
{

	Xhash_context_holder ctx;
	
    uint32_t hashA[16], hashB[16];	
	//blake-bmw-groestl-sken-jh-meccak-luffa-cubehash-shivite-simd-echo
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));
	

    sph_blake512 (&ctx.blake1, input, 80);
    sph_blake512_close (&ctx.blake1, hashA);		

    sph_bmw512 (&ctx.bmw1, hashA, 64);    
    sph_bmw512_close(&ctx.bmw1, hashB);   	
  
    sph_groestl512 (&ctx.groestl1, hashB, 64); 
    sph_groestl512_close(&ctx.groestl1, hashA);
   
    sph_skein512 (&ctx.skein1, hashA, 64); 
    sph_skein512_close(&ctx.skein1, hashB); 
   
    sph_jh512 (&ctx.jh1, hashB, 64); 
    sph_jh512_close(&ctx.jh1, hashA);
  
    sph_keccak512 (&ctx.keccak1, hashA, 64); 
    sph_keccak512_close(&ctx.keccak1, hashB);
	
	sph_luffa512 (&ctx.luffa1, hashB, 64);
    sph_luffa512_close (&ctx.luffa1, hashA);	
    	
    sph_cubehash512 (&ctx.cubehash1, hashA, 64);   
    sph_cubehash512_close(&ctx.cubehash1, hashB);  
	
    sph_shavite512 (&ctx.shavite1, hashB, 64);   
    sph_shavite512_close(&ctx.shavite1, hashA);  
	
	sph_simd512 (&ctx.simd1, hashA, 64);   
    sph_simd512_close(&ctx.simd1, hashB); 
	
	sph_echo512 (&ctx.echo1, hashB, 64);   
    sph_echo512_close(&ctx.echo1, hashA);    

	memcpy(state, hashA, 32);
	
}

int scanhash_X(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{        
 uint32_t n = pdata[19] - 1;
        const uint32_t first_nonce = pdata[19];
        const uint32_t Htarg = ptarget[7];

        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t endiandata[32];
        
        
        int kk=0;
        for (; kk < 32; kk++)
        {
                be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
        };


        if (ptarget[7]==0) {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFFF)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);
        }
        else if (ptarget[7]<=0xF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFFF0)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);
        }
        else if (ptarget[7]<=0xFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFFF00)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);
        }
        else if (ptarget[7]<=0xFFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFFF000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);

        }
        else if (ptarget[7]<=0xFFFF)
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (((hash64[7]&0xFFFF0000)==0) &&
                                        fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);

        }
        else
        {
                do {
                        pdata[19] = ++n;
                        be32enc(&endiandata[19], n);
                        Xhash(hash64, &endiandata);
                        if (fulltest(hash64, ptarget)) {
                                *hashes_done = n - first_nonce + 1;
                                return true;
                        }
                } while (n < max_nonce && !work_restart[thr_id].restart);
        }
        
        
        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}




































