#include "cpuminer-config.h"
#include "miner.h"
#include "scrypt-jane/scrypt-jane.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Constants for YACoin's NFactor
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = 30;

unsigned char GetNfactor(unsigned int nTimestamp) {
    int l = 0;

    if (nTimestamp <= 1367991200)
        return 4;

    unsigned long int s = nTimestamp - 1367991200;
    while ((s >> 1) > 3) {
      l += 1;
      s >>= 1;
    }

    s &= 3;

    int n = (l * 170 + s * 25 - 2320) / 100;

    if (n < 0) n = 0;

    if (n > 255)
        printf("GetNfactor(%d) - something wrong(n == %d)\n", nTimestamp, n);

    unsigned char N = (unsigned char)n;
    //printf("GetNfactor: %d -> %d %d : %d / %d\n", nTimestamp - nChainStartTime, l, s, n, min(max(N, minNfa$

//    return min(max(N, minNfactor), maxNfactor);

    if(N<minNfactor) return minNfactor;
    if(N>maxNfactor) return maxNfactor;
    return N;
}

int scanhash_yacoin(int thr_id, uint32_t *pdata,
        const uint32_t *ptarget,
        uint32_t max_nonce, unsigned long *hashes_done)
{
        uint32_t data[20], hash[8], target_swap[8];
        volatile unsigned char *hashc = (unsigned char *) hash;
        volatile unsigned char *datac = (unsigned char *) data;
        volatile unsigned char *pdatac = (unsigned char *) pdata;
        uint32_t n = pdata[19] - 1;
        int i;

        /* byte swap it */
        for(int z=0;z<20;z++) {
            datac[(z*4)  ] = pdatac[(z*4)+3];
            datac[(z*4)+1] = pdatac[(z*4)+2];
            datac[(z*4)+2] = pdatac[(z*4)+1];
            datac[(z*4)+3] = pdatac[(z*4)  ];
        }

        int nfactor = GetNfactor(data[17]);

        do {
                data[19] = ++n;

                scrypt((unsigned char *)data, 80,
                       (unsigned char *)data, 80,
                       nfactor, 0, 0, (unsigned char *)hash, 32);

                if (hashc[31] == 0 && hashc[30] == 0) {
/*
                    for(int z=7;z>=0;z--)
                       fprintf(stderr, "%08x ", hash[z]);
                    fprintf(stderr, "\n");

                    for(int z=7;z>=0;z--)
                       fprintf(stderr, "%08x ", ptarget[z]);
                    fprintf(stderr, "\n");
*/
                    if(fulltest(hash, ptarget)) {
                        *hashes_done = n - pdata[19] + 1;
                        pdatac[76] = datac[79];
                        pdatac[77] = datac[78];
                        pdatac[78] = datac[77];
                        pdatac[79] = datac[76];
                        return 1;
                   }
                }
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - pdata[19] + 1;
        pdata[19] = n;
        return 0;
}

