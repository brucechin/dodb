/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <pwd.h>
#include <chrono>
// #include <thread>
#include <vector>
// #include <boost/asio.hpp>
#include <string>
#include <algorithm>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#ifdef DEBUG
#define DBGprint(...) printf(__VA_ARGS__)
#else
#define DBGprint(...)
#endif

#define NULLCHAR '\1'

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_status_t status;
// boost::asio::thread_pool pool(4);
// std::atomic_int count;
int rankingsLength = 0, uservisitsLength = 0;
//use these to keep track of all the structures and their types & size
size_t oblivStructureSizes[NUM_STRUCTURES] = {0};
int oblivStructureTypes[NUM_STRUCTURES] = {0};
//hold pointers to start of each oblivious data structure
uint8_t *oblivStructures[NUM_STRUCTURES] = {0};
#define DUMMY '\0'
typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}
// /* Initialize the enclave:
//  *   Call sgx_create_enclave to initialize an enclave instance
//  */
// int initialize_enclave(void)
// {
//     sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
//     /* Call sgx_create_enclave to initialize an enclave instance */
//     /* Debug Support: set 2nd parameter to 1 */
//     ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
//     if (ret != SGX_SUCCESS) {
//         print_error_message(ret);
//         return -1;
//     }

//     return 0;
// }

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[4096] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= 4096)
    {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    }
    else
    {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL)
    {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t))
        {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        if (fp != NULL)
            fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == 0 || fp == NULL)
    {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL)
            fclose(fp);
        return 0;
    }
    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL)
        return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */

    printf("%s", str);
}

void ocall_read_block_batch(int structureId, int index, int batchSize, void *encData, int encDataLen)
{ //read in to buffer

    int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
    int blockSize = sizeof(Linear_Scan_Block);

    //DBGprint("ocall read mem region size %d == %d * %d\n", encDataLen, encBlockSize, batchSize);

    memcpy(encData, oblivStructures[structureId] + ((long)index * encBlockSize), encDataLen);
}

void ocall_write_block_batch(int structureId, int index, int batchSize, void *encData, int encDataLen)
{ //write out from buffer

    int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
    int blockSize = sizeof(Linear_Scan_Block);
    //DBGprint("ocall write mem region size %d == %d * %d\n", encDataLen, encBlockSize, batchSize);
    memcpy(oblivStructures[structureId] + ((long)(index)*encBlockSize), encData, encDataLen);
}

// void ocall_decrypt_batch(int batchSize)
// {
//     int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
//     int blockSize = sizeof(Linear_Scan_Block);

//     int batchSizeEachThread = batchSize / MAX_NUM_THREADS;
//     //DBGprint("batchSize each thread %d\n", batchSizeEachThread);
//     count = 0;
//     //std::vector<int> statusVec(MAX_NUM_THREADS-1, 1);
//     int *statusVec = new int[MAX_NUM_THREADS];
//     memset(statusVec, -1, MAX_NUM_THREADS * sizeof(int));
//     for (int i = 0; i < MAX_NUM_THREADS - 1; i++)
//     {
//         boost::asio::post(pool, [batchSizeEachThread, i, statusVec]() {
//             decryptBlockBatch(global_eid, (int *)&statusVec[i],
//                               batchSizeEachThread * i,
//                               batchSizeEachThread * i,
//                               batchSizeEachThread);
//             count++;
//         });
//     }
//     //in case the batchSize can not be divided by MAX_NUM_THREADS. for example 100 / 16.
//     boost::asio::post(pool, [batchSizeEachThread, batchSize, statusVec]() {
//         decryptBlockBatch(global_eid, (int *)&statusVec[MAX_NUM_THREADS - 1],
//                           batchSizeEachThread * (MAX_NUM_THREADS - 1),
//                           batchSizeEachThread * (MAX_NUM_THREADS - 1),
//                           batchSize - batchSizeEachThread * (MAX_NUM_THREADS - 1));
//         count++;
//     });

//     while (count != MAX_NUM_THREADS)
//     {
//         //DBGprint("waiting decryption during batch reading\n");
//         //std::this_thread::sleep_for(std::chrono::milliseconds(10));
//     }

//     // printf("ocall read status ");

//     // for (int i = 0; i < MAX_NUM_THREADS - 1; i++) {
//     //     printf("%d ", statusVec[i]);
//     // }
//     // printf("\n");
// }

// void ocall_encrypt_batch(int batchSize)
// {
//     int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
//     int blockSize = sizeof(Linear_Scan_Block);
//     int *statusVec = new int[MAX_NUM_THREADS];
//     memset(statusVec, -1, MAX_NUM_THREADS * sizeof(int));
//     int batchSizeEachThread = batchSize / MAX_NUM_THREADS;
//     count = 0;

//     for (int i = 0; i < MAX_NUM_THREADS - 1; i++)
//     {
//         boost::asio::post(pool, [batchSizeEachThread, i, statusVec]() {
//             encryptBlockBatch(global_eid, (int *)&statusVec[i],
//                               batchSizeEachThread * i,
//                               batchSizeEachThread * i,
//                               batchSizeEachThread);
//             count++;
//         });
//     }
//     //in case the batchSize can not be divided by MAX_NUM_THREADS. for example 100 / 16.
//     boost::asio::post(pool, [batchSizeEachThread, batchSize, statusVec]() {
//         encryptBlockBatch(global_eid, (int *)&statusVec[MAX_NUM_THREADS - 1],
//                           batchSizeEachThread * (MAX_NUM_THREADS - 1),
//                           batchSizeEachThread * (MAX_NUM_THREADS - 1),
//                           batchSize - batchSizeEachThread * (MAX_NUM_THREADS - 1));
//         count++;
//     });
//     while (count != MAX_NUM_THREADS)
//     {
//         //DBGprint("waiting encryption during batch writing\n");
//         //std::this_thread::sleep_for(std::chrono::milliseconds(10));

//     }
//     // printf("ocall write status ");
//     // for (int i = 0; i < MAX_NUM_THREADS - 1; i++) {
//     //     printf("%d ", statusVec[i]);
//     // }
//     // printf("\n");
// }

void ocall_read_block(int structureId, int index, void *encData, int encBlockSize)
{ //read in to buffer
    //printf("read mem addr %d\n", &oblivStructures[structureId] + ((long)index * encBlockSize));

    memcpy(encData, oblivStructures[structureId] + ((long)index * encBlockSize), encBlockSize);
    //printf("read mem copy done\n");
}

void ocall_write_block(int structureId, int index, void *encData, int encBlockSize)
{ //write out from buffer
    memcpy(oblivStructures[structureId] + ((long)index * encBlockSize), encData, encBlockSize);
    //printf("write mem copy done\n");
}
//shrink the real allocated untrusted memory region size down to oblivStructureSizes[structureId].
void ocall_updateStructureSize(int structureId, int resize)
{
    int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
    long val = (long)encBlockSize * resize;

    uint8_t *shrinkedStructure = (uint8_t *)malloc(val);
    memcpy(shrinkedStructure, oblivStructures[structureId], val);
    free(oblivStructures[structureId]);
    oblivStructures[structureId] = shrinkedStructure;
}

void ocall_newStructure(int newId, size_t size)
{ //this is actual size, the logical size will be smaller for orams
    int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
    oblivStructureSizes[newId] = size;
    long val = (long)encBlockSize * size;
    oblivStructures[newId] = (uint8_t *)malloc(val);
    if (!oblivStructures[newId])
    {
        printf("failed to allocate space (%ld bytes) for structure\n", val);
        fflush(stdout);
    }
    memset(oblivStructures[newId], 0, val);
}
void ocall_deleteStructure(int structureId)
{
    //memset(oblivStructures[structureId], 0, (long)(oblivStructureSizes[structureId] * sizeof(Encrypted_Linear_Scan_Block)));
    oblivStructureSizes[structureId] = 0;
    oblivStructureTypes[structureId] = 0;
    free(oblivStructures[structureId]); //hold pointers to start of each oblivious data structure
}

void ocall_benchmark(sgx_enclave_id_t enclave_id, int status)
{

    int testLength = 1024 * 1024 * 1;
    int structureId1 = -1;
    Schema rankingsSchema;
    rankingsSchema.numFields = 4;
    rankingsSchema.fieldOffsets[0] = 0;
    rankingsSchema.fieldSizes[0] = 1;
    rankingsSchema.fieldTypes[0] = CHAR;

    rankingsSchema.fieldOffsets[1] = 1;
    rankingsSchema.fieldSizes[1] = 100;
    rankingsSchema.fieldTypes[1] = TINYTEXT;
    rankingsSchema.fieldNames[1] = "pageURL";

    rankingsSchema.fieldOffsets[2] = 101;
    rankingsSchema.fieldSizes[2] = 4;
    rankingsSchema.fieldTypes[2] = INTEGER;
    rankingsSchema.fieldNames[2] = "pageRank";

    rankingsSchema.fieldOffsets[3] = 105;
    rankingsSchema.fieldSizes[3] = 4;
    rankingsSchema.fieldTypes[3] = INTEGER;
    rankingsSchema.fieldNames[3] = "avgDuration";
    char *tableName = "rankings";
    int res = createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), testLength, &structureId1);
    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;
    startTime = std::chrono::high_resolution_clock::now();

    uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
    for (int i = 0; i < testLength; i++)
    {
        memset(row, i, BLOCK_DATA_SIZE);
        //manually insert into the linear scan structure for speed purposes
        opOneLinearScanBlock(enclave_id, (int *)&status, structureId1, i, (Linear_Scan_Block *)row, 0);
    }
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    DBGprint("BLOCK_SIZE %d read/write %d times cost : %.5f seconds\n", BLOCK_DATA_SIZE, testLength, elapsedTime);

    int batchSize = 128;
    while (batchSize <= 10240)
    {
        startTime = std::chrono::high_resolution_clock::now();
        uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
        for (int i = 0; i < testLength; i += batchSize)
        {
            memset(row, i, BLOCK_DATA_SIZE * batchSize);
            //manually insert into the linear scan structure for speed purposes
            opBatchLinearScanBlock(enclave_id, (int *)&status, structureId1, i, batchSize, row, 0);
        }
        endTime = std::chrono::high_resolution_clock::now();
        time_span = endTime - startTime;
        elapsedTime = time_span.count();
        DBGprint("BLOCK_SIZE %d read/write %d times cost : %.5f seconds(batch size %d)\n", BLOCK_DATA_SIZE, testLength, elapsedTime, batchSize);
        batchSize *= 4;
        free(row);
    }
    DBGprint("\n\n");
}

void DPPrefixSumMicrobenchmark(sgx_enclave_id_t enclave_id, int status)
{
    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;
    for (int i = 100; i < 10000000; i *= 4)
    {
        startTime = std::chrono::high_resolution_clock::now();
        DPPrefixSumMicrobenchmark(global_eid, (int *)status, i);
        endTime = std::chrono::high_resolution_clock::now();
        time_span = endTime - startTime;
        elapsedTime = time_span.count();
        printf("%d within-enclave calls of DPPrefixSum running time : %.5f seconds\n", i, elapsedTime);
    }
}

void DOFilterMicrobenchmark(sgx_enclave_id_t enclave_id, int status)
{
    //block size needs to be 512

    //SELECT pageURL, pageRank FROM rankings WHERE pageRank > 200;
    //printTable(global_eid, (int *)status, "rankings");
    Condition cond;
    int val = 1000;
    cond.numClauses = 1;
    cond.fieldIndex[0] = 2;
    cond.conditionType[0] = GREATER;
    cond.values[0] = (uint8_t *)malloc(4);
    memcpy(cond.values[0], &val, 4);
    cond.nextCondition = NULL;

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    DOFilterMicrobenchmark(enclave_id, (int *)&status, "rankings", cond);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOFilterMicrobench - %d - running time - %.5f - seconds\n", rankingsLength, elapsedTime);
}

void DOProjectMicrobenchmark(sgx_enclave_id_t enclave_id, int status)
{
    //block size needs to be 512

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    DOProjectMicrobenchmark(enclave_id, (int *)&status, "rankings");
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOProjectMicrobench - %d - running time - %.5f - seconds\n", rankingsLength, elapsedTime);
}

void DOSortJoinMicrobenchmark(sgx_enclave_id_t enclave_id, int status)
{
    //block size needs to be 512

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    DOSortJoinMicrobenchmark(enclave_id, (int *)&status);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOSortJoinMicrobench - %d - running time - %.5f - seconds\n", rankingsLength, elapsedTime);
}

void orderbyBenchmark(sgx_enclave_id_t enclave_id, int status)
{
    //block size needs to be 512

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    int sortCol[1] = {2};
    orderby(enclave_id, "rankings", sortCol, 1, 0, 0, 1);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();

    printf("BucketObliviousSort - %d - running time - %.5f - seconds(differential oblivious)\n", rankingsLength, elapsedTime);

    startTime = std::chrono::high_resolution_clock::now();
    orderby(enclave_id, "rankings", sortCol, 1, 0, 0, 2);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("BitonicSort - %d - running time - %.5f - seconds(differential oblivious)\n", rankingsLength, elapsedTime);
}

void BDB1(sgx_enclave_id_t enclave_id, int status)
{
    //block size needs to be 512

    //SELECT pageURL, pageRank FROM rankings WHERE pageRank > 200;
    //printTable(global_eid, (int *)status, "rankings");
    Condition cond;
    int val = 1000;
    cond.numClauses = 1;
    cond.fieldIndex[0] = 2;
    cond.conditionType[0] = GREATER;
    cond.values[0] = (uint8_t *)malloc(4);
    memcpy(cond.values[0], &val, 4);
    cond.nextCondition = NULL;

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;
    //Just to warmup cache

    // startTime = std::chrono::high_resolution_clock::now();
    // Q1(enclave_id, (int *)&status, "rankings", cond);
    // endTime = std::chrono::high_resolution_clock::now();
    // time_span = endTime - startTime;
    // elapsedTime = time_span.count();
    // printf("FOBDB1 running time : %.5f(full oblivious. This is FO implementation of mine not ObliDB, but they have similar performance)\n", elapsedTime);

    startTime = std::chrono::high_resolution_clock::now();
    DOQ1(enclave_id, (int *)&status, "rankings", cond);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOBDB1 - %d - running time - %.5f - seconds(differential oblivious)\n", rankingsLength, elapsedTime);
}

void DOGroupbyBenchmark(sgx_enclave_id_t enclave_id, int status)
{
    Condition cond;
    cond.numClauses = 0;
    cond.nextCondition = NULL;
    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;
    //printTable(enclave_id, (int *)&status, "uservisits");
    startTime = std::chrono::high_resolution_clock::now();
    DOSortBasedQ2(enclave_id, (int *)&status, "uservisits", cond);

    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOSortBasedGroupByMicrobench - %d - running time - %.5f - seconds\n\n\n", uservisitsLength, elapsedTime);

    startTime = std::chrono::high_resolution_clock::now();
    DOHashBasedQ2(enclave_id, (int *)&status, "uservisits", cond);

    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOHashBasedGroupbyMicrobench - %d - running time - %.5f - seconds\n\n\n", uservisitsLength, elapsedTime);
}

void BDB2(sgx_enclave_id_t enclave_id, int status)
{
    //REMEMBER TO replace BLOCK_DATA_SIZE with 2048

    Condition cond;
    cond.numClauses = 0;
    cond.nextCondition = NULL;

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    //DOHashBasedQ2(enclave_id, (int *)&status, "uservisits", cond);
    DOSortBasedQ2(enclave_id, (int *)&status, "uservisits", cond);

    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOBDB2 - %d - running time - %.5f - seconds\n\n\n", rankingsLength, elapsedTime);
}

void BDB3(sgx_enclave_id_t enclave_id, int status)
{

    auto startTime = std::chrono::high_resolution_clock::now(), endTime = std::chrono::high_resolution_clock::now();
    double elapsedTime;
    std::chrono::duration<double> time_span;

    startTime = std::chrono::high_resolution_clock::now();
    Q3(enclave_id, (int *)&status);
    endTime = std::chrono::high_resolution_clock::now();
    time_span = endTime - startTime;
    elapsedTime = time_span.count();
    printf("DOBDB3 - %d - running time - %.5f - seconds\n\n", rankingsLength, elapsedTime);
    //fflush(stdout);
    //printPaddingCounter(enclave_id);
}


//TODO more abstraction on table and tuple to support general CSV file auto-loading
void LoadTables(sgx_enclave_id_t enclave_id, int status, char *rankingsFileName, int rankingsLength, char *uservisitsFileName, int uservisitsLength)
{
    //block size 512
    //I have include all table initialization in this function. rankings.csv need BLOCK_DATA_SIZE = 512, uservisits.csv needs BLOCK_DATA_SIZE=2048.
    //In order to support them together, I simply set BLOCK_DATA_SIZE=2048. If we set different BLOCK_DATA_SIZE for different tables, there can be some performance gains
    // int rankingsLength = 5000000;   //rankings table
    // int uservisitsLength = 5000000; //uservisist table
    DBGprint("rankings schema init\n");

    uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
    int structureId1 = -1;
    Schema rankingsSchema;
    rankingsSchema.numFields = 4;
    rankingsSchema.fieldOffsets[0] = 0;
    rankingsSchema.fieldSizes[0] = 1;
    rankingsSchema.fieldTypes[0] = CHAR;

    rankingsSchema.fieldOffsets[1] = 1;
    rankingsSchema.fieldSizes[1] = 100;
    rankingsSchema.fieldTypes[1] = TINYTEXT;
    rankingsSchema.fieldNames[1] = "pageURL";

    rankingsSchema.fieldOffsets[2] = 101;
    rankingsSchema.fieldSizes[2] = 4;
    rankingsSchema.fieldTypes[2] = INTEGER;
    rankingsSchema.fieldNames[2] = "pageRank";

    rankingsSchema.fieldOffsets[3] = 105;
    rankingsSchema.fieldSizes[3] = 4;
    rankingsSchema.fieldTypes[3] = INTEGER;
    rankingsSchema.fieldNames[3] = "avgDuration";
    DBGprint("rankings schema prepared\n");

    char *tableName = "rankings";
    int res = createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), rankingsLength, &structureId1);

    std::ifstream file(rankingsFileName);
    char line[BLOCK_DATA_SIZE]; //make this big just in case
    char data[BLOCK_DATA_SIZE];

    //loading rankings.csv file.
    if (file.is_open())
    {
        DBGprint("rankings opened\n");
        for (int i = 0; i < rankingsLength; i++)
        {
            memset(row, NULLCHAR, BLOCK_DATA_SIZE);
            row[0] = 'a';
            file.getline(line, BLOCK_DATA_SIZE); //get the field
            std::istringstream ss(line);
            for (int j = 0; j < 3; j++)
            {
                if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
                {
                    break;
                }
                if (j == 1 || j == 2)
                { //integer
                    int d = 0;
                    d = atoi(data);
                    memcpy(&row[rankingsSchema.fieldOffsets[j + 1]], &d, 4);
                }
                else
                { //tinytext
                    strncpy((char *)&row[rankingsSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
                }
            }
            //manually insert into the linear scan structure for speed purposes
            opOneLinearScanBlock(enclave_id, (int *)&status, structureId1, i, (Linear_Scan_Block *)row, 1);
        }
        setNumRows(enclave_id, (int *)&status, structureId1, rankingsLength);

        printf("created rankings table\n\n");
    }
    else
    {
        DBGprint("error open file %s\n", tableName);
    }

    int structureId2 = -1;
    Schema userdataSchema;
    userdataSchema.numFields = 10;

    userdataSchema.fieldOffsets[0] = 0;
    userdataSchema.fieldSizes[0] = 1;
    userdataSchema.fieldTypes[0] = CHAR;

    userdataSchema.fieldOffsets[1] = 1;
    userdataSchema.fieldSizes[1] = 100;
    userdataSchema.fieldTypes[1] = TINYTEXT;
    userdataSchema.fieldNames[1] = "destURL";

    userdataSchema.fieldOffsets[2] = 101;
    userdataSchema.fieldSizes[2] = 116;
    userdataSchema.fieldTypes[2] = TINYTEXT;
    userdataSchema.fieldNames[2] = "sourceIP";

    userdataSchema.fieldOffsets[3] = 217;
    userdataSchema.fieldSizes[3] = 4;
    userdataSchema.fieldTypes[3] = INTEGER;
    userdataSchema.fieldNames[3] = "visitDate";

    userdataSchema.fieldOffsets[4] = 221;
    userdataSchema.fieldSizes[4] = 4;
    userdataSchema.fieldTypes[4] = INTEGER;
    userdataSchema.fieldNames[4] = "adRevenue";

    userdataSchema.fieldOffsets[5] = 225;
    userdataSchema.fieldSizes[5] = 200;
    userdataSchema.fieldTypes[5] = TINYTEXT;
    userdataSchema.fieldNames[5] = "userAgent";

    userdataSchema.fieldOffsets[6] = 425;
    userdataSchema.fieldSizes[6] = 3;
    userdataSchema.fieldTypes[6] = TINYTEXT;
    userdataSchema.fieldNames[6] = "countryCode";

    userdataSchema.fieldOffsets[7] = 428;
    userdataSchema.fieldSizes[7] = 6;
    userdataSchema.fieldTypes[7] = TINYTEXT;
    userdataSchema.fieldNames[7] = "languageCode";

    userdataSchema.fieldOffsets[8] = 434;
    userdataSchema.fieldSizes[8] = 32;
    userdataSchema.fieldTypes[8] = TINYTEXT;
    userdataSchema.fieldNames[8] = "searchWord";

    userdataSchema.fieldOffsets[9] = 466;
    userdataSchema.fieldSizes[9] = 4;
    userdataSchema.fieldTypes[9] = INTEGER;
    userdataSchema.fieldNames[9] = "duration";

    char *tableName2 = "uservisits";
    createTable(enclave_id, (int *)&status, &userdataSchema, tableName2, strlen(tableName2), uservisitsLength, &structureId2);

    std::ifstream file2(uservisitsFileName);
    if (file2.is_open())
    {
        int counter = 0;
        DBGprint("uservisits opened\n");
        for (int i = 0; i < uservisitsLength; i++)
        {
            memset(row, NULLCHAR, BLOCK_DATA_SIZE);
            row[0] = 'a';
            file2.getline(line, BLOCK_DATA_SIZE); //get the field

            std::istringstream ss(line);
            for (int j = 0; j < 9; j++)
            {
                if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
                {
                    //printf("ERROR: split line\n");
                    break;
                }
                //DBGprint("data : %s\n", data);
                if (j == 2 || j == 3 || j == 8)
                { //integer
                    int d = 0;
                    if (j == 3)
                    {
                        d = atof(data) * 100;
                        //printf("adRevenue : %d\n", d);
                    }

                    else if (j == 8)
                        d = atoi(data);
                    else
                    { //j == 2, parse the date 1990-01-01 to integer 19900101
                        std::string str_data(data);
                        int year = stoi(str_data.substr(0, 4));
                        int month = stoi(str_data.substr(5, 6));
                        int day = stoi(str_data.substr(8, 9));
                        d = year * 10000 + month * 100 + day;
                        //std::cout << str_data << " " << d  << " " << year << " " << month << " " <<day<< std::endl;
                    }

                    memcpy(&row[userdataSchema.fieldOffsets[j + 1]], &d, 4);
                }
                else if (j == 0)
                {
                    //sourceIP
                    strncpy((char *)&row[userdataSchema.fieldOffsets[2]], data, strlen(data) + 1);
                }
                else if (j == 1)
                {
                    //pageURL
                    //because we replace the sourceIP and pageURL column index, we have to modify loading table scripts
                    strncpy((char *)&row[userdataSchema.fieldOffsets[1]], data, strlen(data) + 1);
                }
                else
                { //tinytext
                    strncpy((char *)&row[userdataSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
                }
            }
            //manually insert into the linear scan structure for speed purposes

            opOneLinearScanBlock(enclave_id, (int *)&status, structureId2, i, (Linear_Scan_Block *)row, 1);
        }
        setNumRows(enclave_id, (int *)&status, structureId2, uservisitsLength);

        printf("created uservisits table\n\n");
    }
    else
    {
        DBGprint("error open file %s\n", tableName2);
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    char *rankingFilename = (char *)(argv[1]);
    char *uservisitsFilename = (char *)(argv[2]);
    rankingsLength = atoi(argv[3]);
    uservisitsLength = atoi(argv[4]);
    int testType = atoi(argv[5]);
    std::cout << "read rankings table " << rankingsLength << " rows, and uservisits " << uservisitsLength << " rows " << MAX_NUM_THREADS << std::endl;
    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    //init secret key
    keyInit(global_eid, &status);
    if (status != SGX_SUCCESS)
    {
        printf("key initialization failed %d.\n", status);
    }
    printf("key init done %d.\n", status);

    LoadTables(global_eid, status, rankingFilename, rankingsLength, uservisitsFilename, uservisitsLength);
    printf("load table done\n");
    //orderbyBenchmark(global_eid, status);
    if (testType == 1)
    {
        // DOFilterMicrobenchmark(global_eid, status);
        // DOProjectMicrobenchmark(global_eid, status);
       //  DOGroupbyBenchmark(global_eid, status);
       //DOSortJoinMicrobenchmark(global_eid, status);
    }
    else
    {
        //BDB series evaluation
        //BDB1(global_eid, status);
        BDB2(global_eid, status);
        // BDB3(global_eid, status);
        // DOGroupbyBenchmark(global_eid, status);
    }

    //deleteTable(global_eid, (int *)&status, "uservisits");
    //deleteTable(global_eid, (int *)&status, "rankings");

    //microbenchmarks here
    //ocall_benchmark(global_eid, status);
    //DPPrefixSumMicrobenchmark(global_eid, status);

    /* Destroy the enclave */
    //sgx_destroy_enclave(global_eid);

    printf("Info: Enclave successfully returned.\n");

    return 0;
}
