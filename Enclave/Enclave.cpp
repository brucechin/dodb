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
#include <stdarg.h>
#include <vector>
#include <stdio.h>	 /* vsnprintf */
#include <thread>	 // std::this_thread::sleep_for
#include <chrono>	 // std::chrono::seconds
#include "Enclave.h" /* print_string */
#include "definitions.h"
#include "hll.h"
#include <random>
#include <cstdlib>
#include <iostream>
#include <ctime>
sgx_aes_gcm_128bit_key_t *obliv_key;

size_t oblivStructureSizes[NUM_STRUCTURES] = {0}; //actual size, not logical size for orams
//specific to database application, hidden from app
Schema schemas[NUM_STRUCTURES] = {0};
char *tableNames[NUM_STRUCTURES] = {0};
uint32_t numRows[NUM_STRUCTURES] = {0}; //number of inserted rows for each table

Linear_Scan_Block *real;
Encrypted_Linear_Scan_Block *realEnc;

uint64_t sort_time = 0;
uint64_t decryption_time = 0;
uint64_t encryption_time = 0;
uint64_t inner_memcpy_time = 0;
uint64_t untrusted_mem_copy_to_enclave_time = 0;
uint64_t enclave_mem_copy_untrusted_time = 0;
uint64_t process_time = 0; //real operator process time within enclave
uint64_t start = 0;
uint64_t end = 0;
int padding_counter = 0;
static inline uint64_t rdtsc(void)
{
	uint32_t hi, lo;

	__asm__ __volatile__("rdtsc"
						 : "=a"(lo), "=d"(hi));

	return (uint64_t(hi) << 32) | uint64_t(lo);
}

void printf(const char *fmt, ...)
{
	char buf[65536] = {DUMMY};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void printPaddingCounter()
{
	printf("padding counter %d\n", padding_counter);
}

void ecallPrintHelloWorld()
{
	ocall_print_string("hello world from enclave inside:)\n");
}

/*
	Start of Enclave_data_structure.cpp(in ObliDB). Some utils functions here
*/
int smallestPowerOfTwoLargerThan(int n)
{
	int k = 1;
	while (k > 0 && k < n)
	{
		k = k << 1;
	}
	return k;
}

void printSchema(Schema schema)
{
	//skip the DUMMY marker column
	for (int i = 1; i < schema.numFields; i++)
	{
		DBGprint("%dth col, name %s, offset %d, len %d, type %d\n", i, schema.fieldNames[i], schema.fieldOffsets[i], schema.fieldSizes[i], schema.fieldTypes[i]);
	}
}

int encryptBlock(void *ct, void *pt)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	//get random IV
	ret = sgx_read_rand(((Encrypted_Linear_Scan_Block *)ct)->iv, 12);
	if (ret != SGX_SUCCESS)
		retVal = 1;
	//encrypt

	ret = sgx_rijndael128GCM_encrypt(obliv_key, (unsigned char *)pt, sizeof(Linear_Scan_Block), ((Encrypted_Linear_Scan_Block *)ct)->ciphertext,
									 ((Encrypted_Linear_Scan_Block *)ct)->iv, 12, NULL, 0, &((Encrypted_Linear_Scan_Block *)ct)->macTag);
	if (ret != SGX_SUCCESS)
	{
		//DBGprint("enc error\n");
		retVal = 1;
	}

	return retVal;
}

int encryptBlockBatch(int ciphertextIndexStart, int plaintextIndexStart, int batchSize)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	//get random IV
	for (int i = 0; i < batchSize; i++)
	{
		//printRow((uint8_t*)(real + plaintextIndexStart + i) ,schemas[0]);
		if (encryptBlock((void *)(realEnc + i + ciphertextIndexStart), (void *)(real + i + plaintextIndexStart)) != 0)
		{
			DBGprint("batch enc error\n");
			return 1;
		}
	}

	return retVal;
}

int decryptBlock(void *ct, void *pt)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	//decrypt
	ret = sgx_rijndael128GCM_decrypt(obliv_key, ((Encrypted_Linear_Scan_Block *)ct)->ciphertext, sizeof(Linear_Scan_Block), (unsigned char *)pt,
									 ((Encrypted_Linear_Scan_Block *)ct)->iv, 12, NULL, 0, &((Encrypted_Linear_Scan_Block *)ct)->macTag);
	if (ret != SGX_SUCCESS)
	{
		//DBGprint("dec error\n");
		retVal = 1;
	}
	//DBGprint("dec pt %10s\n",pt);
	return retVal;
}

int decryptBlockBatch(int ciphertextIndexStart, int plaintextIndexStart, int batchSize)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retVal = 0;
	//decrypt
	for (int i = 0; i < batchSize; i++)
	{
		if (decryptBlock((void *)(realEnc + i + ciphertextIndexStart), (void *)(real + i + plaintextIndexStart)) != 0)
		{
			//DBGprint("batch dec error\n");
			return 1;
		}
	}

	return retVal;
}

int getNextStructureId()
{
	int ret = -1;
	for (int i = 0; i < NUM_STRUCTURES; i++)
	{
		if (oblivStructureSizes[i] == 0)
		{
			return i;
		}
	}
	return ret;
}

sgx_status_t keyInit()
{ //initialize the obliv_key

	obliv_key = (sgx_aes_gcm_128bit_key_t *)malloc(sizeof(sgx_aes_gcm_128bit_key_t));
	return sgx_read_rand((unsigned char *)obliv_key, sizeof(sgx_aes_gcm_128bit_key_t));
}

sgx_status_t initStructure(size_t size, int *structureId)
{ //size in blocks
	sgx_status_t ret = SGX_SUCCESS;
	int newId = getNextStructureId();
	if (newId == -1)
		return SGX_ERROR_UNEXPECTED;
	if (*structureId != -1)
		newId = *structureId;

	oblivStructureSizes[newId] = size;
	ocall_newStructure(newId, size);
	//DBGprint("allocate untrusted memory success\n");
	*structureId = newId;
	return ret;
}

//clean up a structure
sgx_status_t freeStructure(int structureId)
{
	sgx_status_t ret = SGX_SUCCESS;
	oblivStructureSizes[structureId] = 0; //most important since this is what we use to check if a slot is open
	ocall_deleteStructure(structureId);
	return ret;
}


int opBatchLinearScanBlockUnit(int structureId, int index, int batchSize, uint8_t *block, int write){
	int blockSize = sizeof(Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	int idx = index;
	//DBGprint("try to allocate mem for realEnc\n");
	realEnc = (Encrypted_Linear_Scan_Block *)malloc(encBlockSize * batchSize);
	//DBGprint("success allocate mem for realEnc\n");
	//real = (Linear_Scan_Block *)malloc(blockSize * batchSize);
	real = (Linear_Scan_Block *)block;
	if (write)
	{ //we leak whether an op is a read or a write; we could hide it, but it may not be necessary?
		memcpy(real, block, blockSize * batchSize);
		encryptBlockBatch(0, 0, batchSize);
		ocall_write_block_batch(structureId, idx, batchSize, (void *)realEnc, encBlockSize * batchSize);
	}
	else
	{
		ocall_read_block_batch(structureId, idx, batchSize, (void *)realEnc, encBlockSize * batchSize);
		decryptBlockBatch(0, 0, batchSize);
		memcpy(block, real, blockSize * batchSize); //keep the value we extracted from real if we're reading
	}

	//free(real);
	free(realEnc);
}

int opBatchLinearScanBlock(int structureId, int index, int batchSize, uint8_t *block, int write)
{
	int defaultBatchSize = 8192;

	//partition large batch into several smaller ones to execute
	//DBGprint("opBatch split larger batch into smaller ones\n");
	uint8_t *pointer = block;
	for (int i = 0; i < batchSize; i += defaultBatchSize)
	{
		opBatchLinearScanBlockUnit(structureId, index + i, std::min(defaultBatchSize, batchSize - i), pointer, write);
		pointer += defaultBatchSize * sizeof(Linear_Scan_Block);
	}

	return 0;
}

int opOneLinearScanBlock(int structureId, int index, Linear_Scan_Block *block, int write)
{

	int blockSize = sizeof(Linear_Scan_Block);
	int encBlockSize = sizeof(Encrypted_Linear_Scan_Block);
	int i = index;
	real = (Linear_Scan_Block *)malloc(blockSize);
	realEnc = (Encrypted_Linear_Scan_Block *)malloc(encBlockSize);
	if (write)
	{ //we leak whether an op is a read or a write; we could hide it, but it may not be necessary?
		memcpy(real->data, block, BLOCK_DATA_SIZE);
		//DBGprint("opwrite pt %10s\n",real);

		if (encryptBlock((void *)realEnc, (void *)real) != 0)
			return 1;
		ocall_write_block(structureId, i, realEnc, encBlockSize);
		//DBGprint("write : enc row %s, dec row%s\n", realEnc->ciphertext, real->data);
	}
	else
	{
		ocall_read_block(structureId, i, realEnc, encBlockSize);

		//DBGprint("read : enc row %s, dec row%s\n", realEnc->ciphertext, real->data);
		if (decryptBlock((void *)realEnc, (void *)real) != 0)
			return 1;
		memcpy(block, real->data, BLOCK_DATA_SIZE); //keep the value we extracted from real if we're reading
	}

	free(real);
	free(realEnc);

	return 0;
}

inline void CMOV4_internal(const uint64_t cond, uint32_t& guy1, const uint32_t& guy2) {
  asm volatile("test %[mcond], %[mcond]\n\t"
               "cmovnz %[i2], %[i1]\n\t"
               : [i1] "=r"(guy1)
               : [mcond] "r"(cond), "[i1]" (guy1), [i2] "r"(guy2)
               : );
}


inline void CMOV1(const bool& cond, uint8_t& val1, const uint8_t& val2) {
  uint32_t r1 = 0 | val1;
  uint32_t r2 = 0 | val2;
  CMOV4_internal(cond, r1, r2);
  val1 = r1 & 0xff;
}

inline void CMOV1(const bool& cond, uint32_t& val1, const uint32_t& val2) {
  uint32_t r1 = 0 | val1;
  uint32_t r2 = 0 | val2;
  CMOV4_internal(cond, r1, r2);
  val1 = r1;
}

// used for the tuple block movement
void ObliMov(bool mov, uint8_t* guy1, uint8_t* guy2) {
  uint8_t* curr1 = (uint8_t*)guy1;
  uint8_t* curr2 = (uint8_t*)guy2;
  for (uint64_t i = 0; i < BLOCK_DATA_SIZE; i++) {
    CMOV1(mov, *curr1, *curr2);
    curr1++;
    curr2++;
  }
}

// used for the tuple block movement
void ObliMov(bool mov, uint32_t* guy1, uint32_t* guy2, int num_blocks) {
  uint8_t* curr1 = (uint8_t*)guy1;
  uint8_t* curr2 = (uint8_t*)guy2;
  for (uint64_t i = 0; i < num_blocks; i++) {
    CMOV1(mov, *curr1, *curr2);
    curr1++;
    curr2++;
  }
}

inline void CXCHG(const bool& cond, uint8_t* A, uint8_t* B) {
  uint8_t* C = (uint8_t *)malloc(BLOCK_DATA_SIZE);
  memcpy(C, A, BLOCK_DATA_SIZE);
  ObliMov(cond, A, B);
  ObliMov(cond, B, C);
  free(C);
}



//limitSize means only output the top XXX rows.
void bucketObliviousSort(int inputStructureId, std::vector<int> sortColIndex, bool ascendant)
{

	int capacity = oblivStructureSizes[inputStructureId];
	int bucketNum = smallestPowerOfTwoLargerThan(ceil(2.0 * capacity / BIN_SIZE));
	int randomBinAssignmentIterations = log2(bucketNum) - 1;
	int rowsOfEachBucket = (capacity / bucketNum) + 1;
	int batchSize = BIN_SIZE;
	//default sort column offset and length
	std::vector<int> sortColOffset;
	std::vector<int> sortColLen;
	std::vector<DB_Type> sortColType;
	for (int i = 0; i < sortColIndex.size(); i++)
	{
		sortColOffset.push_back(schemas[inputStructureId].fieldOffsets[sortColIndex[i]]);
		sortColLen.push_back(schemas[inputStructureId].fieldSizes[sortColIndex[i]]);
		sortColType.push_back(schemas[inputStructureId].fieldTypes[sortColIndex[i]]);
	}

	//DBGprint("sort column index %d, offset %d, length %d\n", sortColIndex, sortColOffset, sortColLen);
	//DBGprint("input table %d rows, bucketNu, %d, iterations %d\n", capacity, bucketNum, randomBinAssignmentIterations);

	// in the original algorithm, we should allocate log2(bucketNum) + 1 arrays. But two is enough if we keep reusing the previous old array.
	std::vector<int> bucketStuctureIdArray1 = std::vector<int>(bucketNum, -1);
	std::vector<int> bucketStuctureIdArray2 = std::vector<int>(bucketNum, -1);
	for (int i = 0; i < bucketNum; i++)
	{
		initStructure(BIN_SIZE, &bucketStuctureIdArray1[i]);
		initStructure(BIN_SIZE, &bucketStuctureIdArray2[i]);
	}
	//DBGprint("init bins success\n");
	uint8_t *readBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	printf("start allocate randomKey\n");
	for (int i = 0; i < capacity; i += batchSize)
	{
		opBatchLinearScanBlock(inputStructureId, i, std::min(batchSize, int(capacity - i)), readBuffer, 0);
		uint8_t *readBufPointer = readBuffer;
		int32_t randomKey;
		for (int j = 0; j < std::min(batchSize, int(capacity - i)); j++)
		{
			sgx_read_rand((unsigned char *)&randomKey, 4);
			//store the random key at the end of each row.
			memcpy(readBufPointer + BLOCK_DATA_SIZE - 4, &randomKey, 4);
			//DBGprint("randomKey %d\n", randomKey);
			opOneLinearScanBlock(bucketStuctureIdArray1[(i + j) % bucketNum], numRows[bucketStuctureIdArray1[(i + j) % bucketNum]], (Linear_Scan_Block *)readBufPointer, 1);
			readBufPointer += BLOCK_DATA_SIZE;
			bool real = readBufPointer[0] != DUMMY;
			uint32_t new_count = numRows[bucketStuctureIdArray1[(i + j) % bucketNum]] ;
			uint32_t new_count2 = numRows[bucketStuctureIdArray1[(i + j) % bucketNum]] + 1;
			CMOV1(real, new_count , new_count2);
			numRows[bucketStuctureIdArray1[(i + j) % bucketNum]] = new_count;
			
		}
	}

	free(readBuffer);
	//dummy writes to each buckets until full.
	for (int i = 0; i < bucketNum; i++)
	{
		//DBGprint("bucket %d has %d real rows\n", i, numRows[bucketStuctureIdArray1[i]]);
		//printTableById(bucketStuctureIdArray1[i], schemas[inputStructureId]);
		padWithDummy(bucketStuctureIdArray1[i], numRows[bucketStuctureIdArray1[i]]);
	}
	printf("end allocate randomKey\n");

	printf("start random bin assignment\n");
	for (int i = 0; i < randomBinAssignmentIterations; i++)
	{

		if (i % 2 == 0)
		{
			for (int j = 0; j < bucketNum / 2; j++)
			{
				int jj = (j / (int)pow(2, i)) * (int)pow(2, i);
				DBGprint("%dth merge out of %d merges. jj is %d, input bucket %d, %d into output bucket %d, %d\n", j, 8, jj, j + jj, j + jj + (int)pow(2, i), 2 * j, 2 * j + 1);
				mergeSplit(bucketStuctureIdArray1[j + jj], bucketStuctureIdArray1[j + jj + (int)pow(2, i)], bucketStuctureIdArray2[2 * j], bucketStuctureIdArray2[2 * j + 1], i);
			}
			int count = 0;
			for (int k = 0; k < bucketNum; k++)
			{
				numRows[bucketStuctureIdArray1[k]] = 0; //clean the bucketStuctureIdArray1 for next iteration
				count += numRows[bucketStuctureIdArray2[k]];
			}
			printf("after %dth merge split, we have %d tuples\n", i, count);
		}
		else
		{
			for (int j = 0; j < bucketNum / 2; j++)
			{
				int jj = (j / (int)pow(2, i)) * (int)pow(2, i);

				DBGprint("%dth merge out of %d merges. jj is %d, input bucket %d, %d into output bucket %d, %d\n", j, 8, jj, j + jj, j + jj + (int)pow(2, i), 2 * j, 2 * j + 1);

				mergeSplit(bucketStuctureIdArray2[j + jj], bucketStuctureIdArray2[j + jj + (int)pow(2, i)], bucketStuctureIdArray1[2 * j], bucketStuctureIdArray1[2 * j + 1], i);
			}
			int count = 0;
			for (int k = 0; k < bucketNum; k++)
			{
				numRows[bucketStuctureIdArray2[k]] = 0; //clean the bucketStuctureIdArray1 for next iteration
				count += numRows[bucketStuctureIdArray1[k]];
			}
			printf("after %dth merge split, we have %d tuples\n", i, count);
		}

		DBGprint("\n\nfinish random bin assignmen iter %dth out of %d\n\n", i, randomBinAssignmentIterations);
	}
	printf("end random bin assignment\n");

	//int outputStructureId = -1;
	//createTable(&schemas[inputStructureId], outputTableName, sizeof(outputTableName), oblivStructureSizes[inputStructureId], &outputStructureId);
	//write back to the original input table to save memory
	numRows[inputStructureId] = 0; //reset to zero for writing back


	//because we have done random bin assignment, now we do non-oblivious sort on the entire array.
	printf("start  bin sort\n");
	if (randomBinAssignmentIterations % 2 == 1)
	{
		for (int i = 0; i < bucketNum; i++)
		{
			DBGprint("start sort %d bucket\n", i);
			bucketSort(bucketStuctureIdArray2[i], sortColOffset, sortColLen, sortColType, ascendant);
			//free the other array to save memory for final merge sort step
			freeStructure(bucketStuctureIdArray1[i]);
			//DBGprint("delete %dth bucket\n", i);
			//printTableById(bucketStuctureIdArray2[i], schemas[inputStructureId]);
		}

		kWayMergeSort(bucketStuctureIdArray2, inputStructureId, sortColOffset, sortColLen, sortColType, ascendant);
	}
	else
	{
		for (int i = 0; i < bucketNum; i++)
		{
			DBGprint("start sort %d bucket\n", i);
			bucketSort(bucketStuctureIdArray1[i], sortColOffset, sortColLen, sortColType, ascendant);
			freeStructure(bucketStuctureIdArray2[i]);
			//DBGprint("delete %dth bucket\n", i);
			//printTableById(bucketStuctureIdArray1[i], schemas[inputStructureId]);
		}

		kWayMergeSort(bucketStuctureIdArray1, inputStructureId, sortColOffset, sortColLen, sortColType, ascendant);
	}
	printf("end  bin sort\n");

	//correctness passed
	//checkFinalSortCorrectness(inputStructureId, sortColOffset, sortColLen, sortColType, ascendant);
}

int printCmpValHelper(uint8_t *row, int sortColOffset, int sortColLen)
{
	int val = 0;
	memcpy(&val, row + sortColOffset, sortColLen);
	return val;
}

void checkFinalSortCorrectness(int outputStructureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant)
{
	int size = numRows[outputStructureId];
	DBGprint("check final sort correctness, table size %d\n", size);
	uint8_t *buf1 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *buf2 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	opOneLinearScanBlock(outputStructureId, 0, (Linear_Scan_Block *)buf1, 0);
	for (int i = 1; i < size; i++)
	{
		//DBGprint("check sort %d\n", i);
		opOneLinearScanBlock(outputStructureId, i, (Linear_Scan_Block *)buf2, 0);
		//DBGprint("check sort read success %d\n", i);

		if (cmpHelper(buf1, buf2, sortColOffset, sortColLen, sortColType, ascendant))
		{
			DBGprint("error on %dth val (%d, %d)\n", i, printCmpValHelper(buf1, sortColOffset[0], sortColLen[0]), printCmpValHelper(buf2, sortColOffset[0], sortColLen[0]));
		}

		//DBGprint("check sort cmp success %d\n", i);
		memcpy(buf1, buf2, BLOCK_DATA_SIZE);
		//DBGprint("check sort memcpy success %d\n", i);
	}

	free(buf1);
	free(buf2);
}
void kWayMergeSort(std::vector<int> structureIdVec, int outputStructureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant)
{
	int mergeSortBatchSize = 256;
	int writeBufferSize = 8192;
	int numWays = structureIdVec.size();
	HeapNode inputHeapNodeArr[numWays];
	int totalCounter = 0;

	for (int i = 0; i < numWays; i++)
	{
		HeapNode node;
		node.data = (uint8_t *)malloc(BLOCK_DATA_SIZE * mergeSortBatchSize);
		node.bucket = i;
		node.index = 0;
		opBatchLinearScanBlock(structureIdVec[i], 0, std::min((uint32_t)mergeSortBatchSize, numRows[structureIdVec[i]] - 0), node.data, 0);

		inputHeapNodeArr[i] = node;
	}
	Heap heap(inputHeapNodeArr, numWays, mergeSortBatchSize, sortColOffset, sortColLen, sortColType, ascendant);
	DBGprint("init heap success\n");
	uint8_t *writeBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBufferSize);
	int writeBufferCounter = 0;
	while (1)
	{
		HeapNode *tmp = heap.getRoot();
		memcpy(writeBuffer + BLOCK_DATA_SIZE * writeBufferCounter, tmp->data + BLOCK_DATA_SIZE * (tmp->index % mergeSortBatchSize), BLOCK_DATA_SIZE);
		writeBufferCounter++;
		totalCounter++;
		tmp->index++; // move to next unprocessed element
		if (writeBufferCounter == writeBufferSize)
		{
			opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBufferSize, writeBuffer, 1);
			numRows[outputStructureId] += writeBufferSize;
			writeBufferCounter = 0;
		}

		if (tmp->index < numRows[structureIdVec[tmp->bucket]] && (tmp->index % mergeSortBatchSize) == 0)
		{
			//DBGprint("bucket %d, index %d, numRows %d\n", structureIdVec[tmp->bucket], tmp->index, numRows[structureIdVec[tmp->bucket]]);
			opBatchLinearScanBlock(structureIdVec[tmp->bucket], tmp->index, std::min((uint32_t)mergeSortBatchSize, numRows[structureIdVec[tmp->bucket]] - tmp->index), tmp->data, 0);
			//opOneLinearScanBlock(structureIdVec[tmp->bucket], tmp->index, (Linear_Scan_Block *)tmp->data, 0);
			//DBGprint("%dth bucket, %dth row into heap \n", tmp->bucket, tmp->index);
			heap.Heapify(0);
		}
		else if (tmp->index >= numRows[structureIdVec[tmp->bucket]])
		{
			bool res = heap.reduceSizeByOne();
			if (!res)
			{
				//we have processed all buckets.
				break;
			}
		}
		else
		{
			//index has been incremented, need to re-heapify
			// start = rdtsc();
			heap.Heapify(0);
			// end = rdtsc();
			// process_time += end - start;
		}
	}

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBufferCounter, writeBuffer, 1);
	numRows[outputStructureId] += writeBufferCounter;

	free(writeBuffer);

	//TODO free buckets when not performance benchmarking

	//for performance reason we can leave the memory garbage collection out of time measurement range.

	// for (int i = 0; i < structureIdVec.size(); i++)
	// {
	// 	freeStructure(structureIdVec[i]);
	// 	DBGprint("delete %dth bucket\n", i);
	// }
}


// This is in-enclave oblivious sort to replace quick sort.
void bitonicSortForBucket(uint8_t* arr, int low, int high, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant){
	// we know the size can be held within the enclave for sure here.
	if(high - low == 0){
		return; //end of recursion.
	}

	int mid = greatestPowerOfTwoLessThan(high - low + 1);
	// printf("low %d, high %d, mid %d\n", low, high, mid);
	for(int i = low; i < high - mid + 1  ; i++){
		uint8_t* left = arr +  i * BLOCK_DATA_SIZE;
		uint8_t* right = arr + (mid + i) * BLOCK_DATA_SIZE;
		bool swap = cmpHelper(left, right, sortColOffset, sortColLen, sortColType, ascendant);
		CXCHG(swap, left, right); // oblivious swap here.
	}

	bitonicSortForBucket(arr, low, low + mid - 1, sortColOffset, sortColLen,sortColType,  ascendant);
	bitonicSortForBucket(arr, low + mid , high, sortColOffset, sortColLen,sortColType,  ascendant);

}


void bucketSort(int structureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant)
{
	uint8_t *arr = (uint8_t *)malloc(BLOCK_DATA_SIZE * BIN_SIZE);
	DBGprint("bucket sort on %d structure which has %d real rows\n", structureId, numRows[structureId]);
	//printTableById(structureId, schemas[0]);
	opBatchLinearScanBlock(structureId, 0, numRows[structureId], arr, 0);
	printf("bucket sort read bucket\n");
	// start = rdtsc();


	//quickSort(arr, 0, numRows[structureId] - 1, sortColOffset, sortColLen, sortColType, ascendant);
	//printf("bitonic sort bucket number of rows %d\n", numRows[structureId]);
	bitonicSortForBucket(arr, 0, numRows[structureId] - 1, sortColOffset, sortColLen, sortColType, ascendant);

	// end = rdtsc();
	// process_time += end - start;
	printf("sort success, write back\n");
	opBatchLinearScanBlock(structureId, 0, numRows[structureId], arr, 1);
	//printTableById(structureId, schemas[0]);
	free(arr);
}

int partition(uint8_t *arr, int low, int high, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant)
{
	uint8_t *pivot = arr + high * BLOCK_DATA_SIZE;
	int i = (low - 1);
	for (int j = low; j <= high - 1; j++)
	{
		//DBGprint("start comp %d and %d\n", high, j);
		if (cmpHelper(pivot, arr + j * BLOCK_DATA_SIZE, sortColOffset, sortColLen, sortColType, ascendant))
		{
			i++;
			if (i != j)
			{
				swapRow(arr + i * BLOCK_DATA_SIZE, arr + j * BLOCK_DATA_SIZE);
			}
		}
	}
	if (i + 1 != high)
	{
		swapRow(arr + (i + 1) * BLOCK_DATA_SIZE, arr + high * BLOCK_DATA_SIZE);
	}
	return (i + 1);
}

void quickSort(uint8_t *arr, int low, int high, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant)
{
	//this recursive version is correct
	if (high - low > 0)
	{
		int mid = partition(arr, low, high, sortColOffset, sortColLen, sortColType, ascendant);
		quickSort(arr, low, mid - 1, sortColOffset, sortColLen, sortColType, ascendant);
		quickSort(arr, mid + 1, high, sortColOffset, sortColLen, sortColType, ascendant);
	}
}

//swap row a and row b, row size is BLOCK_DATA_SIZE
void swapRow(uint8_t *a, uint8_t *b)
{
	uint8_t *tmp = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	// DBGprint("\nSWAP\n");
	// printRow(a, schemas[0]);
	// printRow(b, schemas[0]);
	// DBGprint("\n");
	memmove(tmp, a, BLOCK_DATA_SIZE);
	memmove(a, b, BLOCK_DATA_SIZE);
	memmove(b, tmp, BLOCK_DATA_SIZE);
	free(tmp);
}

//return true if we need to swap
bool cmpHelper(uint8_t *a, uint8_t *b, std::vector<int> offsets, std::vector<int> lens, std::vector<DB_Type> types, bool asc)
{
	for (int k = 0; k < offsets.size(); k++)
	{
		switch (types[k])
		{
		case INTEGER:
			int aa, bb;
			memcpy(&aa, a + offsets[k], 4);
			memcpy(&bb, b + offsets[k], 4);
			//DBGprint("%dth cmp INTEGER %d, %d\n", k, aa, bb);
			if ((aa > bb && asc) || (aa < bb && !asc))
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		case CHAR:
			char aaa, bbb;
			memcpy(&aaa, a + offsets[k], 1);
			memcpy(&bbb, b + offsets[k], 1);
			if ((aaa > bbb && asc) || (aaa < bbb && !asc))
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		case TINYTEXT:
			uint8_t *pa = a + offsets[k];
			uint8_t *pb = b + offsets[k];
			if (((memcmp((char *)pa, (char *)pb, lens[k]) > 0) && asc) || ((memcmp((char *)pa, (char *)pb, lens[k]) && !asc)))
			{
				return true;
			}
			else if (memcmp((char *)pa, (char *)pb, lens[k]) == 0)
			{
				//DBGprint("Same %10s, %10s, jump to next sort column for comparison\n", a, b);

				//do nothing and check next sort column
			}
			else
			{
				return false;
			}

			break;
		}
	}
	return false;
}

bool isTagetBitOne(int input, int index)
{
	if (input & (1 << (index)))
	{
		return true;
	}
	else
	{
		return false;
	}
}

void mergeSplitHelper(uint8_t *inputBuffer, int inputBufferLen, int outputStructureId0, int outputStructureId1, int iter)
{

	uint8_t *inputBufPointer = inputBuffer;
	int batchSize = 8192;
	uint8_t *buf1 = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	uint8_t *buf0 = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	int counter1 = 0;
	int counter0 = 0;
	int randomKey = 0;
	int counter = 0;
	for (int i = 0; i < inputBufferLen; i++)
	{
		// DBGprint("start %d\n",i);
		if (inputBufPointer[0] != DUMMY)
		{

			memcpy(&randomKey, inputBufPointer + BLOCK_DATA_SIZE - 4, 4); //get the random key
			if (isTagetBitOne(randomKey, iter + 1))
			{
				// opOneLinearScanBlock(outputStructureId1, numRows[outputStructureId1], (Linear_Scan_Block *)inputBufPointer, 1);
				// numRows[outputStructureId1]++;
				memcpy(buf1 + counter1 * BLOCK_DATA_SIZE, inputBufPointer, BLOCK_DATA_SIZE);
				counter1++;

				if (counter1 == batchSize)
				{
					// DBGprint("insert output1\n");
					opBatchLinearScanBlock(outputStructureId1, numRows[outputStructureId1], batchSize, buf1, 1);
					numRows[outputStructureId1] += batchSize;
					counter1 = 0;
					memset(buf1, NULLCHAR, BLOCK_DATA_SIZE * batchSize);
				}
			}
			else
			{
				// opOneLinearScanBlock(outputStructureId0, numRows[outputStructureId0], (Linear_Scan_Block *)inputBufPointer, 1);
				// numRows[outputStructureId0]++;
				memcpy(buf0 + counter0 * BLOCK_DATA_SIZE, inputBufPointer, BLOCK_DATA_SIZE);
				counter0++;
				if (counter0 == batchSize)
				{
					// DBGprint("insert output0\n");
					opBatchLinearScanBlock(outputStructureId0, numRows[outputStructureId0], batchSize, buf0, 1);
					numRows[outputStructureId0] += batchSize;
					counter0 = 0;
					memset(buf0, NULLCHAR, BLOCK_DATA_SIZE * batchSize);
				}
			}
		}
		inputBufPointer += BLOCK_DATA_SIZE;
	}
	DBGprint("final write back\n");
	//write back the rest
	opBatchLinearScanBlock(outputStructureId1, numRows[outputStructureId1], counter1, buf1, 1);
	numRows[outputStructureId1] += counter1;
	opBatchLinearScanBlock(outputStructureId0, numRows[outputStructureId0], counter0, buf0, 1);
	numRows[outputStructureId0] += counter0;

	free(buf0);
	free(buf1);
}

void mergeSplit(int inputStructureId0, int inputStructureId1, int outputStructureId0, int outputStructureId1, int iter)
{
	uint8_t *inputBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * BIN_SIZE);
	DBGprint("mergeSplit input %d, %d have %d, %d rows, output %d, %d have %d, %d rows\n", inputStructureId0, inputStructureId1, numRows[inputStructureId0], numRows[inputStructureId1], outputStructureId0, outputStructureId1, numRows[outputStructureId0], numRows[outputStructureId1]);
	// printTableById(inputStructureId0, schemas[0]);
	// printTableById(inputStructureId1, schemas[0]);
	opBatchLinearScanBlock(inputStructureId0, 0, BIN_SIZE, inputBuffer, 0);
	DBGprint("finish reading\n");
	mergeSplitHelper(inputBuffer, numRows[inputStructureId0], outputStructureId0, outputStructureId1, iter);
	DBGprint("merge first half\n");
	if (numRows[outputStructureId0] > BIN_SIZE || numRows[outputStructureId1] > BIN_SIZE)
	{
		DBGprint("overflow error during merge split!\n");
	}

	opBatchLinearScanBlock(inputStructureId1, 0, BIN_SIZE, inputBuffer, 0);
	mergeSplitHelper(inputBuffer, numRows[inputStructureId1], outputStructureId0, outputStructureId1, iter);

	if (numRows[outputStructureId0] > BIN_SIZE || numRows[outputStructureId1] > BIN_SIZE)
	{
		DBGprint("overflow error during merge split!\n");
	}
	DBGprint("merge second half\n");

	padWithDummy(outputStructureId1, numRows[outputStructureId1]);
	padWithDummy(outputStructureId0, numRows[outputStructureId0]);
	
	// printTableById(outputStructureId0, schemas[0]);
	// printTableById(outputStructureId1, schemas[0]);
	DBGprint("padding\n");

	//DBGprint("mergeSplit input %d, %d have %d, %d rows, output %d, %d have %d, %d rows\n", inputStructureId0, inputStructureId1, numRows[inputStructureId0], numRows[inputStructureId1], outputStructureId0, outputStructureId1, numRows[outputStructureId0], numRows[outputStructureId1]);
	free(inputBuffer);
}

void padWithDummy(int structureId, int startIndex)
{
	int blockSize = sizeof(Linear_Scan_Block);
	int len = (oblivStructureSizes[structureId] - startIndex);
	DBGprint("padding with dummy len %d \n", len);
	uint8_t *junk = (uint8_t *)malloc(blockSize * len);
	memset(junk, DUMMY, blockSize * len);
	opBatchLinearScanBlock(structureId, startIndex, len, junk, 1);
	free(junk);
}

int incrementNumRows(int structureId)
{
	numRows[structureId]++;
	return 0;
}

int setNumRows(int structureId, int numRow)
{
	numRows[structureId] = numRow;
	return 0;
}

int createTable(Schema *schema, char *tableName, int nameLen, int numberOfRows, int *structureId)
{
	//structureId should be -1 unless we want to force a particular structure for testing
	sgx_status_t retVal = SGX_SUCCESS;
	DBGprint("start creating table name %s, tuple size %d, capacity %d\n", tableName, getRowSize(schema), numberOfRows);

	//validate schema a little bit
	if (schema->numFields > MAX_COLS)
		return 1;
	int rowSize = getRowSize(schema);

	if (rowSize <= 0)
		return rowSize;
	if (BLOCK_DATA_SIZE / rowSize == 0)
	{ //can't fit a row in a block of the data structure!
		return 4;
	}

	numberOfRows += (numberOfRows == 0);
	int initialSize = numberOfRows;
	retVal = initStructure(initialSize, structureId);
	if (retVal != SGX_SUCCESS)
		return 5;

	//size & type are set in initStructure, but we need to initiate the rest
	tableNames[*structureId] = (char *)malloc(nameLen + 1);
	strncpy(tableNames[*structureId], tableName, nameLen + 1);
	memcpy(&schemas[*structureId], schema, sizeof(Schema));
	numRows[*structureId] = 0;
	DBGprint("created table name %s, id %d, capacity %d\n", tableName, *structureId, numberOfRows);
	return 0;
}

int deleteTableById(int structureId)
{
	freeStructure(structureId);
	free(tableNames[structureId]);
	numRows[structureId] = 0;
	schemas[structureId] = {0};
	return 0;
}

int deleteTable(char *tableName)
{
	int structureId = getTableId(tableName);
	freeStructure(structureId);
	free(tableNames[structureId]);
	numRows[structureId] = 0;
	schemas[structureId] = {0};
	return 0;
}

int getTableId(char *tableName)
{
	for (int i = 0; i < NUM_STRUCTURES; i++)
	{
		if (tableNames[i] != NULL && strcmp(tableName, tableNames[i]) == 0)
		{
			return i;
		}
		//DBGprint("%10s is not %dth table\n", tableName, i);
	}
	return -1;
}

Schema getTableSchema(char *tableName)
{
	int structureId = getTableId(tableName);
	return schemas[structureId];
}

int getNumRows(int structureId)
{
	return numRows[structureId];
}

size_t getTableCapacity(int structureId)
{
	return oblivStructureSizes[structureId];
}

int printRow(uint8_t *row, Schema schema)
{
	// printf("|  ");
	// for (int j = 1; j < schema.numFields; j++)
	// {
	// 	switch (schema.fieldTypes[j])
	// 	{
	// 	case INTEGER:
	// 		printf("%10s", schema.fieldNames[j]);
	// 		break;
	// 	case CHAR:
	// 		printf("%10c", schema.fieldNames[j]);
	// 		break;
	// 	case TINYTEXT:
	// 		printf("%80s", schema.fieldNames[j]);
	// 	}
	// 	printf("  |");
	// }
	//printf("\n\n");
	if (row[0] != DUMMY)
	{
		//skip dummy rows for printing out

		printf("|  ");
		for (int j = 1; j < schema.numFields; j++)
		{
			switch (schema.fieldTypes[j])
			{
			case INTEGER:
				int temp;
				memcpy(&temp, &row[schema.fieldOffsets[j]], 4);
				printf("%10d", temp);
				break;
			case CHAR:
				printf("%10c", row[schema.fieldOffsets[j]]);
				break;
			case TINYTEXT:
				printf("%50s", &row[schema.fieldOffsets[j]]); // TODO to make print out on the same line, I reduce the size from 255 to 100
				break;
			}
			printf("  |  ");
		}
		//printf("\n\n");
	}
	return 0;
}

int printTableById(int structureId, Schema schema)
{
	//REMINDER : this is non-oblivious version that's good for debugging
	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	printf("\nTable %s, %d rows, capacity for %d rows, stored in structure %d\n", tableNames[structureId], numRows[structureId], oblivStructureSizes[structureId], structureId);
	printf("|  ");
	for (int j = 1; j < schema.numFields; j++)
	{
		switch (schema.fieldTypes[j])
		{
		case INTEGER:
			printf("%10s", schema.fieldNames[j]);
			break;
		case CHAR:
			printf("%10c", schema.fieldNames[j]);
			break;
		case TINYTEXT:
			printf("%100s", schema.fieldNames[j]);
		}
		printf("  |");
	}
	//printf("\n");
	for (int i = 0; i < oblivStructureSizes[structureId]; i++)
	{
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block *)row, 0);
		if (row[0] == DUMMY)
		{
			//skip dummy rows for printing out
			continue;
		}
		printf("|  ");
		for (int j = 1; j < schema.numFields; j++)
		{
			switch (schema.fieldTypes[j])
			{
			case INTEGER:
				int temp;
				memcpy(&temp, &row[schema.fieldOffsets[j]], 4);
				printf("%10d", temp);
				break;
			case CHAR:
				printf("%10c", row[schema.fieldOffsets[j]]);
				break;
			case TINYTEXT:
				printf("%100s", &row[schema.fieldOffsets[j]]); // TODO to make print out on the same line, I reduce the size from 255 to 100
				break;
			}
			printf("  |  ");
		}
		//printf("\n");
	}
	free(row);
	return 0;
}

int printTable(char *tableName)
{
	//REMINDER : this is non-oblivious version that's good for debugging
	int structureId = getTableId(tableName);
	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	printf("\nTable %s, %d rows, capacity for %d rows, stored in structure %d\n", tableNames[structureId], numRows[structureId], oblivStructureSizes[structureId], structureId);
	printf("|  ");
	for (int j = 1; j < schemas[structureId].numFields; j++)
	{
		switch (schemas[structureId].fieldTypes[j])
		{
		case INTEGER:
			printf("%10s", schemas[structureId].fieldNames[j]);
			break;
		case CHAR:
			printf("%10c", schemas[structureId].fieldNames[j]);
			break;
		case TINYTEXT:
			printf("%80s", schemas[structureId].fieldNames[j]);
		}
		printf("  |");
	}
	//printf("\n");
	for (int i = 0; i < oblivStructureSizes[structureId]; i++)
	{
		opOneLinearScanBlock(structureId, i, (Linear_Scan_Block *)row, 0);
		if (row[0] == DUMMY)
		{
			//skip dummy rows for printing out
			continue;
		}
		printf("|  ");
		for (int j = 1; j < schemas[structureId].numFields; j++)
		{
			switch (schemas[structureId].fieldTypes[j])
			{
			case INTEGER:
				int temp;
				memcpy(&temp, &row[schemas[structureId].fieldOffsets[j]], 4);
				printf("%10d", temp);
				break;
			case CHAR:
				printf("%10c", row[schemas[structureId].fieldOffsets[j]]);
				break;
			case TINYTEXT:
				printf("%80s", &row[schemas[structureId].fieldOffsets[j]]); // TODO to make print out on the same line, I reduce the size from 255 to 100
				break;
			}
			printf("  |  ");
		}
		//printf("\n");
	}
	free(row);
	return 0;
}
int DOQ1(char *tableName, Condition c)
{
	padding_counter = 0;

	//differential oblivious Q1
	int structureId = getTableId(tableName);
	Schema inputSchema = getTableSchema(tableName);

	//set output schema(dummy, pageURL, pageRank)
	int columnsToProjected[3] = {0, 1, 2};
	Schema outSchema;
	outSchema.numFields = 3;
	//dummy column
	outSchema.fieldOffsets[0] = 0;
	outSchema.fieldSizes[0] = 1;
	outSchema.fieldTypes[0] = CHAR;
	outSchema.fieldNames[0] = "dummy";

	//pageURL column
	outSchema.fieldOffsets[1] = 1;
	outSchema.fieldSizes[1] = 100;
	outSchema.fieldTypes[1] = TINYTEXT;
	outSchema.fieldNames[1] = "pageURL";

	//pageRank column
	outSchema.fieldOffsets[2] = 101;
	outSchema.fieldSizes[2] = 4;
	outSchema.fieldTypes[2] = INTEGER;
	outSchema.fieldNames[2] = "pageRank";

	char *returnTableName2 = "DOQ1";

	DOProjectWithFilter(structureId, returnTableName2, c, inputSchema, outSchema, columnsToProjected);
	//printTable(returnTableName2);
	//deleteTable(returnTableName2);
	return 0;
}

int DOProjectMicrobenchmark(char *tableName)
{

	int structureId = getTableId(tableName);
	Schema inputSchema = getTableSchema(tableName);

	//set output schema(dummy, pageURL, pageRank)
	int columnsToProjected[3] = {0, 1, 2};
	Schema outSchema;
	outSchema.numFields = 3;
	//dummy column
	outSchema.fieldOffsets[0] = 0;
	outSchema.fieldSizes[0] = 1;
	outSchema.fieldTypes[0] = CHAR;
	outSchema.fieldNames[0] = "dummy";
	//pageURL column
	outSchema.fieldOffsets[1] = 1;
	outSchema.fieldSizes[1] = 100;
	outSchema.fieldTypes[1] = TINYTEXT;
	outSchema.fieldNames[1] = "pageURL";

	//pageRank column
	outSchema.fieldOffsets[2] = 101;
	outSchema.fieldSizes[2] = 4;
	outSchema.fieldTypes[2] = INTEGER;
	outSchema.fieldNames[2] = "pageRank";

	char *returnTableName = "Q1";

	DOProject(structureId, returnTableName, inputSchema, outSchema, columnsToProjected);
	//printTable(returnTableName);
	//deleteTable(returnTableName);
	return 0;
}

int DOFilterMicrobenchmark(char *tableName, Condition c)
{

	int structureId = getTableId(tableName);
	char *returnTableName = "Q1";

	DOFilter(structureId, returnTableName, c);
	//printTable(returnTableName);
	//deleteTable(returnTableName);
	return 0;
}

int DOSortJoinMicrobenchmark()
{
	char *rightTableName = "uservisits";
	char *leftTableName = "rankings";
	int joinColLeft = 1;
	int joinColRight = 1;
	int rightStructureId = getTableId(rightTableName);
	Schema inputSchema = getTableSchema("uservisits");

	//set output schema(dummy, sourceIP, destURL, visitDate, adRevenue)
	int columnsToProjected[5] = {0, 1, 2, 3, 4};
	Schema projectedUservisitsSchema;
	projectedUservisitsSchema.numFields = 5;
	for (int i = 0; i < projectedUservisitsSchema.numFields; i++)
	{
		projectedUservisitsSchema.fieldOffsets[i] = inputSchema.fieldOffsets[columnsToProjected[i]];
		projectedUservisitsSchema.fieldSizes[i] = inputSchema.fieldSizes[columnsToProjected[i]];
		projectedUservisitsSchema.fieldTypes[i] = inputSchema.fieldTypes[columnsToProjected[i]];
		projectedUservisitsSchema.fieldNames[i] = inputSchema.fieldNames[columnsToProjected[i]];
	}

	int lessThan = 19830101; // Date is loaded as integer
	int greaterThan = 19800101;

	char *projectedUservisits = "projectedUservisits";
	Condition cond;
	cond.numClauses = 2;
	cond.conditionType[0] = LESS;
	cond.fieldIndex[0] = 3;
	cond.values[0] = (uint8_t *)malloc(4);
	memcpy(cond.values[0], &lessThan, 4);
	cond.conditionType[1] = GREATER;
	cond.fieldIndex[1] = 3;
	cond.values[1] = (uint8_t *)malloc(4);
	memcpy(cond.values[1], &greaterThan, 4);
	cond.nextCondition = NULL;

	//STEP1 project useful columns for next JOIN step
	DOProjectWithFilter(rightStructureId, projectedUservisits, cond, inputSchema, projectedUservisitsSchema, columnsToProjected);
	//printTable(projectedUservisits);
	// printTable(leftTableName);
	//printf("project and filtered uservisits table num of rows : %d\n\n\n", numRows[getTableId(projectedUservisits)]);
	deleteTable(rightTableName); //save memory for largest dataset benchmark, or 64GB is not enough.
	//STEP2 join the projected uservisits table and rankings table


	DOSortJoinWithForeginKey(leftTableName, projectedUservisits, "JoinReturn", joinColLeft, joinColRight);
	//printTable("JoinReturn");
	return 0;
}

int Q1(char *tableName, Condition c)
{
	padding_counter = 0;
	int structureId = getTableId(tableName);
	Schema inputSchema = getTableSchema(tableName);

	//set output schema(dummy, pageURL, pageRank)
	int columnsToProjected[3] = {0, 1, 2};
	Schema outSchema;
	outSchema.numFields = 3;
	//dummy column
	outSchema.fieldOffsets[0] = 0;
	outSchema.fieldSizes[0] = 1;
	outSchema.fieldTypes[0] = CHAR;
	outSchema.fieldNames[0] = "dummy";
	//pageURL column
	outSchema.fieldOffsets[1] = 1;
	outSchema.fieldSizes[1] = 100;
	outSchema.fieldTypes[1] = TINYTEXT;
	outSchema.fieldNames[1] = "pageURL";

	//pageRank column
	outSchema.fieldOffsets[2] = 101;
	outSchema.fieldSizes[2] = 4;
	outSchema.fieldTypes[2] = INTEGER;
	outSchema.fieldNames[2] = "pageRank";

	char *returnTableName = "Q1";

	FOProjectWithFilter(structureId, returnTableName, c, inputSchema, outSchema, columnsToProjected);
	//printTable(returnTableName);
	//deleteTable(returnTableName);
	return 0;
}

int DOSortBasedQ2(char *tableName, Condition c)
{
	padding_counter = 0;

	//SELECT SUBSTR(sourceIP, 1, 8), SUM(adRevenue) FROM uservisits GROUP BY SUBSTR(sourceIP, 1, 8)
	std::vector<AggregateType> aggregateType = {SUM, AVG};
	std::vector<int> afield = {4, 9}; //adRevenue, duration
	int gfield = 2;					  // sourceIP
	int substrLen = 8;
	char *returnTableName = "SortQ2";

	DOSortBasedGroupBy(tableName, returnTableName, aggregateType, afield, gfield, substrLen);
	//printTable(returnTableName);
	//deleteTable(returnTableName);
	return 0;
}

int DOHashBasedQ2(char *tableName, Condition c)
{
	padding_counter = 0;

	//SELECT SUBSTR(sourceIP, 1, 8), SUM(adRevenue), AVG(duration) FROM uservisits GROUP BY SUBSTR(sourceIP, 1, 8)
	std::vector<AggregateType> aggregateType = {SUM, AVG};
	std::vector<int> afield = {4, 9}; //adRevenue, duration
	int gfield = 2;					  // sourceIP
	int substrLen = 16;
	char *returnTableName = "HashQ2";
	//printTable("uservisits");
	DOHashBasedGroupBy(tableName, returnTableName, aggregateType, afield, gfield, substrLen);
	//printTable(returnTableName);
	//deleteTable(returnTableName);

	return 0;
}

int Q3()
{
	padding_counter = 0;

	char *rightTableName = "uservisits";
	char *leftTableName = "rankings";
	int joinColLeft = 1;
	int joinColRight = 1;
	int rightStructureId = getTableId(rightTableName);
	Schema inputSchema = getTableSchema("uservisits");

	//set output schema(dummy, sourceIP, destURL, visitDate, adRevenue)
	int columnsToProjected[5] = {0, 1, 2, 3, 4};
	Schema projectedUservisitsSchema;
	projectedUservisitsSchema.numFields = 5;
	for (int i = 0; i < projectedUservisitsSchema.numFields; i++)
	{
		projectedUservisitsSchema.fieldOffsets[i] = inputSchema.fieldOffsets[columnsToProjected[i]];
		projectedUservisitsSchema.fieldSizes[i] = inputSchema.fieldSizes[columnsToProjected[i]];
		projectedUservisitsSchema.fieldTypes[i] = inputSchema.fieldTypes[columnsToProjected[i]];
		projectedUservisitsSchema.fieldNames[i] = inputSchema.fieldNames[columnsToProjected[i]];
	}

	int lessThan = 19830101; // Date is loaded as integer
	int greaterThan = 19800101;

	char *projectedUservisits = "projectedUservisits";
	Condition cond;
	cond.numClauses = 2;
	cond.conditionType[0] = LESS;
	cond.fieldIndex[0] = 3;
	cond.values[0] = (uint8_t *)malloc(4);
	memcpy(cond.values[0], &lessThan, 4);
	cond.conditionType[1] = GREATER;
	cond.fieldIndex[1] = 3;
	cond.values[1] = (uint8_t *)malloc(4);
	memcpy(cond.values[1], &greaterThan, 4);
	cond.nextCondition = NULL;

	//STEP1 project useful columns for next JOIN step
	// DOProjectWithFilter(rightStructureId, projectedUservisits, cond, inputSchema, projectedUservisitsSchema, columnsToProjected);
	// //printTable(projectedUservisits);
	// // printTable(leftTableName);
	// printf("project and filtered uservisits table num of rows : %d\n\n\n", numRows[getTableId(projectedUservisits)]);
	// deleteTable(rightTableName); //save memory for largest dataset benchmark, or 64GB is not enough.
	//STEP2 join the projected uservisits table and rankings table
	DOSortJoinWithForeginKey(leftTableName, rightTableName, "JoinReturn", joinColLeft, joinColRight);
	//printTable("JoinReturn");

	//TODO delete previous intermediate useless tables to save memory
	//STEP3 group by uservisits.sourceIP
	// DOHashBasedGroupBy("JoinReturn", "HashGroupByReturnTable", std::vector<AggregateType>{AVG, SUM}, std::vector<int>{2, 6}, 4, 8);
	// printf("groupby result table num of rows : %d\n\n\n", numRows[getTableId("HashGroupByReturnTable")]);
	// int sortCol[1] = {2};
	// orderby("HashGroupByReturnTable", sortCol, 1, 0, 1, 1);
	//printTable("HashGroupByReturnTable");
	printPaddingCounter();
	//in place orderby

	//deleteTable("HashGroupByReturnTable");
	//deleteTable("JoinReturn");
	//deleteTable("projectedUservisits");

	return 0;
}

int DPPrefixSumMicrobenchmark(int times)
{
	int batchSize = 8192;
	PrefixSumOracle oracle(batchSize, 1.0);
	for (int i = 0; i < 128 * times; i += 128)
	{
		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), i % 100);
		oracle.getDPPrefixSum(i + batchSize);
	}
	return 0;
}

// limitSize means only output top XXX rows
// in order to save more memory space, this is an in-place orderby which means ordered table will be written back to their original place
void orderby(char *tableName, int *sortColIndex, int numSortCols, int ascendant, int limitSize, int algorithm)
{
	int inputStructureId = getTableId(tableName);
	int enclaveSortCapacity = 65536;
	//TODO if we have order by xxx limit y(y is smaller than enclave capacity) desc, we can have a nmax heap of 10 elements within enclave to iterate through the table just once.
	std::vector<int> sortColIndexVec(sortColIndex, sortColIndex + numSortCols);
	std::vector<int> sortColOffset;
	std::vector<int> sortColLen;
	std::vector<DB_Type> sortColType;
	for (int i = 0; i < sortColIndexVec.size(); i++)
	{
		sortColOffset.push_back(schemas[inputStructureId].fieldOffsets[sortColIndexVec[i]]);
		sortColLen.push_back(schemas[inputStructureId].fieldSizes[sortColIndexVec[i]]);
		sortColType.push_back(schemas[inputStructureId].fieldTypes[sortColIndexVec[i]]);
	}
	DBGprint("orderby input table numRows : %d\n", numRows[inputStructureId]);
	if (numRows[inputStructureId] < enclaveSortCapacity)
	{
		//if table for sorting can fit in enclave memory, we use single bucket sort within enclave to do this. this is an optimization for small table sorting
		bucketSort(inputStructureId, sortColOffset, sortColLen, sortColType, ascendant);
	}
	else
	{
		//if table size is larger than what enclave memory can hold. we use other oblivious sorting algorithms.
		if (algorithm == 1)
		{
			bucketObliviousSort(inputStructureId, sortColIndexVec, ascendant % 2);
			DBGprint("bucket oblivious sort finish, output size %d\n", inputStructureId);
		}
		else
		{
			//oblidb bitonic sort
			char *outputTableName = "orderbyReturnTable2";
			uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			uint8_t *row1 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			uint8_t *row2 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			int realRetStructId = -1;
			createTable(&schemas[inputStructureId], outputTableName, strlen(outputTableName), numRows[inputStructureId], &realRetStructId);
			for (int i = 0; i < numRows[inputStructureId]; i++)
			{
				opOneLinearScanBlock(inputStructureId, i, (Linear_Scan_Block *)row, 0);
				memcpy(&row[BLOCK_DATA_SIZE - 8], &row[schemas[inputStructureId].fieldOffsets[sortColIndexVec[0]]], 4);
				opOneLinearScanBlock(realRetStructId, i, (Linear_Scan_Block *)row, 1);
			}
			DBGprint("finish rewriting\n");
			bitonicSort(realRetStructId, 0, numRows[inputStructureId], 0, row1, row2, sortColIndexVec);
		}
	}
}

int filter_counter = 0;
// WHERE operator, return true if row satisfies the condition.
int filter(uint8_t *row, Schema s, Condition c)
{
	int sat = 1;
	for (int i = 0; i < c.numClauses; i++)
	{
		//TODO currently, for multiple filter rules, we return f_1 AND f_2 ... AND f_n. We should support combination of complex conditions  like f_1 AND f_2 OR f_3 eventually
		switch (s.fieldTypes[c.fieldIndex[i]])
		{
		case INTEGER:
			int val, cond;
			memcpy(&val, &row[s.fieldOffsets[c.fieldIndex[i]]], 4);
			memcpy(&cond, c.values[i], 4);
			//DBGprint("val -- cond : %d, %d， offset %d\n", val, cond, s.fieldOffsets[c.fieldIndex[i]]);
			if (c.conditionType[i] == EQUAL)
			{ //equality
				if (val == cond)
				{
					sat *= 1;
				}
				else
				{
					sat *= 0;
				}
			}
			else if (c.conditionType[i] == GREATER)
			{ //row val is greater than
				if (val > cond)
				{
					sat *= 1;
				}
				else
				{
					sat *= 0;
				}
			}
			else if (c.conditionType[i] == LESS)
			{ //row val is less than
				if (val < cond)
				{
					//DBGprint("true val -- cond : %d, %d\n", val, cond);

					sat *= 1;
				}
				else
				{
					//DBGprint("false val -- cond : %d, %d\n", val, cond);

					sat *= 0;
				}
			}
			else if (c.conditionType[i] == GREATEROREQUAL)
			{
				if (val >= cond)
				{
					sat *= 1;
				}
				else
				{
					sat *= 0;
				}
			}
			else if (c.conditionType[i] == LESSOREQUAL)
			{
				if (val <= cond)
				{
					sat *= 1;
				}
				else
				{
					sat *= 0;
				}
			}
			else
			{ //NOT EQUAL
				if (val != cond)
				{
					sat *= 1;
				}
				else
				{
					sat *= 0;
				}
			}
			break;
		case TINYTEXT: //only check equality
			if (strncmp((char *)(&row[s.fieldOffsets[c.fieldIndex[i]]]), (char *)c.values[i], 255) == 0)
			{
				sat *= 1;
			}
			else
			{
				sat *= 0;
			}
			break;
		case CHAR: //only check equality
			if (row[s.fieldOffsets[c.fieldIndex[i]]] == *(c.values[i]))
			{
				sat *= 1;
			}
			else
			{
				sat *= 0;
			}
			break;
		}
	}
	//the order of these ifs is important
	if (c.numClauses == 0)
		sat = 1; //case there is no condition
	if (row[0] == DUMMY)
	{
		sat = 0; //case row is deleted/dummy
		DBGprint("filter meets DUMMY row\n");
	}

	if (!sat)
		return 0;
	else
	{
		filter_counter++;
		//DBGprint("filter counter %d\n", filter_counter);
		return 1;
	}
}

// SELECT operator
void projection(uint8_t *input, uint8_t *output, Schema input_schema, Schema output_schema, int *columnsToProjected)
{
	//remember the first column indicates whether this row is dummy or not.
	for (int i = 0; i < output_schema.numFields; i++)
	{
		//do some checking before memcpy
		if (input_schema.fieldSizes[columnsToProjected[i]] == output_schema.fieldSizes[i] && input_schema.fieldTypes[columnsToProjected[i]] == output_schema.fieldTypes[i])
		{
			memcpy(&output[output_schema.fieldOffsets[i]], &input[input_schema.fieldOffsets[columnsToProjected[i]]], input_schema.fieldSizes[columnsToProjected[i]]);
		}
		else
		{
			DBGprint("fieldSize %d == %d? , fieldType %d == %d? Projection schema not match!\n ", input_schema.fieldSizes[columnsToProjected[i]], output_schema.fieldOffsets[i], input_schema.fieldTypes[columnsToProjected[i]], output_schema.fieldTypes[i]);
			return;
		}
	}
	// printRow(input, input_schema);
	// printRow(output, output_schema);
}

//Differentially oblivious version
void DOProject(int inputStructureId, char *outputTableName, Schema input_schema, Schema output_schema, int *columnsToProjected)
{
	//reset timer

	double epsilon = 1.0;
	//batchSize must be 2^k.
	int batchSize = 65536;
	int outputStructureId = -1;
	int out = createTable(&output_schema, outputTableName, strlen(outputTableName), numRows[inputStructureId] + batchSize * 10, &outputStructureId);

	uint8_t *readBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	std::queue<Linear_Scan_Block *> resultBuffer; //store projection and filtered tuples.
	DBGprint("table size %d, numRealRows %d\n", oblivStructureSizes[inputStructureId], numRows[inputStructureId]);
	PrefixSumOracle oracle(batchSize, epsilon);
	int tableCapacity = oblivStructureSizes[inputStructureId];

	for (int i = 0; i < tableCapacity; i += batchSize)
	{
		opBatchLinearScanBlock(inputStructureId, i, std::min(batchSize, tableCapacity - i), readBuffer, 0);

		//DBGprint("end read %dth batch\n", i);
		Linear_Scan_Block *readBufPointer = (Linear_Scan_Block *)readBuffer;
		int count = 0;
		for (int j = 0; j < std::min(batchSize, tableCapacity - i); j++)
		{
			if (*(uint8_t *)readBufPointer != DUMMY)
			{
				//projection operates directly on the read buffer.
				projection((uint8_t *)readBufPointer->data, (uint8_t *)readBufPointer->data, input_schema, output_schema, columnsToProjected);

				//TODO this temporary allocated enclave memory code seems ugly, but if i directly save the pointer to the projected row address in readBuf, there are possibilities that before they are written back to
				//TODO untrusted memory, it will be overwritten by another opBatchLinearScanBlock(). I have tested that this will not affected performance much if filter selectivity is small.
				Linear_Scan_Block *tmp = (Linear_Scan_Block *)malloc(BLOCK_DATA_SIZE);
				memcpy(tmp, readBufPointer, BLOCK_DATA_SIZE);
				resultBuffer.push(tmp);
				count++;
			}
			readBufPointer++; //move to next tuple.
		}
		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), count);
		float dpPrefixSum = oracle.getDPPrefixSum(i + batchSize);
		//DBGprint("processed index %d,numRows[outputStructureId] %d, dpPrefixSum %f, resultBuffer size %d\n", std::min(i + batchSize - 1, tableCapacity), numRows[outputStructureId], dpPrefixSum, resultBuffer.size());

		//DBGprint("numrows %d, dpPrefixSum - batchSize %f\n", numRows[outputStructureId], dpPrefixSum - batchSize);
		if (numRows[outputStructureId] < dpPrefixSum - batchSize)
		{
			//write back some result rows.
			int writeBackSize = 0;
			if (resultBuffer.size() > dpPrefixSum - batchSize - numRows[outputStructureId])
			{
				//write back part of result buffer to make numRows[outputStructureId] == dpPrefixSum - batchSize
				writeBackSize = dpPrefixSum - batchSize - numRows[outputStructureId];
			}
			else
			{
				//write back all of the result buffer
				DBGprint("privacy failure!\n");
				writeBackSize = resultBuffer.size();
			}
			//DBGprint("%d batch--output size %d, dpPrefixSum %f--find the %dth match\n", i / batchSize, numRows[outputStructureId], dpPrefixSum, numRows[outputStructureId]);
			if (writeBackSize > 0)
			{
				uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
				int index = 0;
				while (index < writeBackSize)
				{
					Linear_Scan_Block *writeBackRow = resultBuffer.front();
					resultBuffer.pop();
					memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
					index++;
					free(writeBackRow);
				}

				opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);
				numRows[outputStructureId] += writeBackSize;
				free(writeBackBatch);
			}
		}
	}

	//If we reach the end of the input, pop all the remaining tuples in the working buffer to theoutput,
	//then write dummy tuples to the output till the output reaches size Y_N+batchSize
	//batched version
	int writeBackSize = resultBuffer.size();
	uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
	int index = 0;
	while (index < writeBackSize)
	{
		Linear_Scan_Block *writeBackRow = resultBuffer.front();
		resultBuffer.pop();
		memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
		index++;
		free(writeBackRow);
	}
	//DBGprint("Final cleanup start-- currently numRows %d\n", numRows[outputStructureId]);

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);

	numRows[outputStructureId] += writeBackSize;
	free(writeBackBatch);
	//DBGprint("Final cleanup done-- currently numRows %d\n", numRows[outputStructureId]);

	//batched version
	float finalPrefixSum;
	if (oblivStructureSizes[inputStructureId] % batchSize != 0)
	{
		finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[inputStructureId] / batchSize + 1) * batchSize);
	}
	else
	{
		finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[inputStructureId] / batchSize) * batchSize);
	}

	int dummySize = (int)finalPrefixSum + batchSize - numRows[outputStructureId];
	DBGprint("insert %d dummy rows\n", dummySize);
	uint8_t *dummyBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * dummySize);
	memset(dummyBatch, DUMMY, BLOCK_DATA_SIZE * dummySize);

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], dummySize, dummyBatch, 1);

	//DBGprint("start update result size from %d to %d\n" ,oblivStructureSizes[outputStructureId], dummySize + numRows[outputStructureId]);
	oblivStructureSizes[outputStructureId] = dummySize + numRows[outputStructureId]; // oblivStructureSizes is capacity. numRows is number of real rows.
	ocall_updateStructureSize(outputStructureId, oblivStructureSizes[outputStructureId]);

	free(readBuffer);
	free(dummyBatch);
}

void DOFilter(int inputStructureId, char *outputTableName, Condition c)
{

	Schema schema = getTableSchema(tableNames[inputStructureId]);
	double epsilon = 1.0;
	//batchSize must be 2^k.
	int batchSize = 65536;
	int outputStructureId = -1;
	if (numRows[inputStructureId] < batchSize * 10)
	{
		int out = createTable(&schema, outputTableName, strlen(outputTableName), batchSize * 10, &outputStructureId);
	}
	else
	{
		int out = createTable(&schema, outputTableName, strlen(outputTableName), numRows[inputStructureId], &outputStructureId);
	}

	uint8_t *readBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	std::queue<Linear_Scan_Block *> resultBuffer; //store projection and filtered tuples.
	DBGprint("table size %d, numRealRows %d\n", oblivStructureSizes[inputStructureId], numRows[inputStructureId]);
	PrefixSumOracle oracle(batchSize, epsilon);
	int tableCapacity = oblivStructureSizes[inputStructureId];

	for (int i = 0; i < tableCapacity; i += batchSize)
	{
		opBatchLinearScanBlock(inputStructureId, i, std::min(batchSize, tableCapacity - i), readBuffer, 0);

		//DBGprint("end read %dth batch\n", i);
		Linear_Scan_Block *readBufPointer = (Linear_Scan_Block *)readBuffer;
		int count = 0;
		for (int j = 0; j < std::min(batchSize, tableCapacity - i); j++)
		{

			if ((filter((uint8_t *)readBufPointer->data, schema, c) == 1) && *(uint8_t *)readBufPointer != DUMMY)
			{
				//projection operates directly on the read buffer.
				//TODO this temporary allocated enclave memory code seems ugly, but if i directly save the pointer to the projected row address in readBuf, there are possibilities that before they are written back to
				//TODO untrusted memory, it will be overwritten by another opBatchLinearScanBlock(). I have tested that this will not affected performance much if filter selectivity is small.
				Linear_Scan_Block *tmp = (Linear_Scan_Block *)malloc(BLOCK_DATA_SIZE);
				memcpy(tmp, readBufPointer, BLOCK_DATA_SIZE);
				resultBuffer.push(tmp);
				count++;
			}
			readBufPointer++; //move to next tuple.
		}
		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), count);
		float dpPrefixSum = oracle.getDPPrefixSum(i + batchSize);
		//DBGprint("processed index %d,numRows[outputStructureId] %d, dpPrefixSum %f, resultBuffer size %d\n", std::min(i + batchSize - 1, tableCapacity), numRows[outputStructureId], dpPrefixSum, resultBuffer.size());

		//DBGprint("numrows %d, dpPrefixSum - batchSize %f\n", numRows[outputStructureId], dpPrefixSum - batchSize);
		if (numRows[outputStructureId] < dpPrefixSum - batchSize)
		{
			//write back some result rows.
			int writeBackSize = 0;
			if (resultBuffer.size() > dpPrefixSum - batchSize - numRows[outputStructureId])
			{
				//write back part of result buffer to make numRows[outputStructureId] == dpPrefixSum - batchSize
				writeBackSize = dpPrefixSum - batchSize - numRows[outputStructureId];
			}
			else
			{
				//write back all of the result buffer
				DBGprint("privacy failure!\n");
				writeBackSize = resultBuffer.size();
			}
			//DBGprint("%d batch--output size %d, dpPrefixSum %f--find the %dth match\n", i / batchSize, numRows[outputStructureId], dpPrefixSum, numRows[outputStructureId]);
			if (writeBackSize > 0)
			{
				uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
				int index = 0;
				while (index < writeBackSize)
				{
					Linear_Scan_Block *writeBackRow = resultBuffer.front();
					resultBuffer.pop();
					memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
					index++;
					free(writeBackRow);
				}
				opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);
				numRows[outputStructureId] += writeBackSize;
				free(writeBackBatch);
			}
		}
	}

	//If we reach the end of the input, pop all the remaining tuples in the working buffer to theoutput,
	//then write dummy tuples to the output till the output reaches size Y_N+batchSize
	//batched version
	int writeBackSize = resultBuffer.size();
	uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
	int index = 0;
	while (index < writeBackSize)
	{
		Linear_Scan_Block *writeBackRow = resultBuffer.front();
		resultBuffer.pop();
		memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
		index++;
		free(writeBackRow);
	}
	//DBGprint("Final cleanup start-- currently numRows %d\n", numRows[outputStructureId]);

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);

	numRows[outputStructureId] += writeBackSize;
	free(writeBackBatch);
	//DBGprint("Final cleanup done-- currently numRows %d\n", numRows[outputStructureId]);

	//batched version
	float finalPrefixSum;
	if (oblivStructureSizes[inputStructureId] % batchSize != 0)
	{
		finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[inputStructureId] / batchSize + 1) * batchSize);
	}
	else
	{
		finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[inputStructureId] / batchSize) * batchSize);
	}

	int dummySize = (int)finalPrefixSum + batchSize - numRows[outputStructureId];
	DBGprint("DOFilter inserts %d dummy rows\n", dummySize);
	uint8_t *dummyBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * dummySize);
	memset(dummyBatch, DUMMY, BLOCK_DATA_SIZE * dummySize);

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], dummySize, dummyBatch, 1);
	DBGprint("DOFilter selectivity : %d / %d, padding size : %d\n", numRows[outputStructureId], oblivStructureSizes[inputStructureId], dummySize);
	//DBGprint("start update result size from %d to %d\n" ,oblivStructureSizes[outputStructureId], dummySize + numRows[outputStructureId]);
	oblivStructureSizes[outputStructureId] = dummySize + numRows[outputStructureId]; // oblivStructureSizes is capacity. numRows is number of real rows.
	ocall_updateStructureSize(outputStructureId, oblivStructureSizes[outputStructureId]);

	free(readBuffer);
	free(dummyBatch);
}

//combine tuple-level filter and projection opeator into table level processing
//SELECT col1, col2...col_n FROM table WHERE predicate
//non-oblivious version. However, it will do a first pass to calculate the cardinality
//fulll oblivious
void FOProjectWithFilter(int inputStructureId, char *outputTableName, Condition c, Schema input_schema, Schema output_schema, int *columnsToProjected)
{
	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *outRow = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *dummy = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	memset(dummy, DUMMY, BLOCK_DATA_SIZE);
	int outputStructureId = -1;
	int out = createTable(&output_schema, outputTableName, strlen(outputTableName), oblivStructureSizes[inputStructureId], &outputStructureId);

	for (int i = 0; i < oblivStructureSizes[inputStructureId]; i++)
	{
		opOneLinearScanBlock(inputStructureId, i, (Linear_Scan_Block *)row, 0);
		row = ((Linear_Scan_Block *)row)->data;
		if ((filter(row, input_schema, c) == 1) && row[0] != DUMMY)
		{
			projection(row, outRow, input_schema, output_schema, columnsToProjected);
			opOneLinearScanBlock(outputStructureId, numRows[outputStructureId], (Linear_Scan_Block *)outRow, 1);
			DBGprint("find the %dth match on the %dth row \n", numRows[outputStructureId], i);
			numRows[outputStructureId]++; //update the num of rows for return table
		}
		else
		{
			//dummy write to stay full oblivious
			opOneLinearScanBlock(outputStructureId, numRows[outputStructureId], (Linear_Scan_Block *)dummy, 1);
		}
	}
}




//This bitonic sort is used in DO Filter to move real tuples to front
void bitonic_sort_deque(std::deque<Linear_Scan_Block*>& input, int start, int size){
	// we know the size can be held within the enclave for sure here.
	if(size == 1){
		return; //end of recursion.
	}
	int mid = greatestPowerOfTwoLessThan(size);
	// DBGprint("start start %d, size %d\n", start, size);
	for(int i = 0; i < size - mid; i++){
		//the first char of the tuple indicates whether it is a dummy or real tuple.
		uint8_t* left = input[start + i]->data;
		uint8_t* right = input[start + mid + i]->data;
		bool swap = left[0] < right[0];
		CXCHG(swap, left, right); // oblivious swap here.
	}
	// DBGprint("end start %d, size %d\n", start, size);

	bitonic_sort_deque(input, start, mid);
	bitonic_sort_deque(input, start + mid, size - mid);
}

//This bitonic sort is used in DO Filter to move real tuples to front
void bitonic_sort_vector(std::vector<Linear_Scan_Block*>& input, int start, int size){
	// we know the size can be held within the enclave for sure here.
	if(size == 1){
		return; //end of recursion.
	}
	//printf("try to find mid\n");
	int mid = greatestPowerOfTwoLessThan(size);
	//printf("start, start %d, size %d\n", start, size);
	for(int i = 0; i < size - mid; i++){
		//the first char of the tuple indicates whether it is a dummy or real tuple.
		uint8_t* left = input[start + i]->data;
		uint8_t* right = input[start + mid + i]->data;
		bool swap = left[0] < right[0];
		CXCHG(swap, left, right); // oblivious swap here.
	}
	//printf("end, start %d, size %d\n", start, size);

	bitonic_sort_vector(input, start, mid);
	bitonic_sort_vector(input, start + mid, size - mid);
}


//Differentially oblivious version
void DOProjectWithFilter(int inputStructureId, char *outputTableName, Condition c, Schema input_schema, Schema output_schema, int *columnsToProjected)
{

	double epsilon = 1.02;
	//batchSize must be 2^k.
	int batchSize = 1024;
	int outputStructureId = -1;

	int out = createTable(&output_schema, outputTableName, strlen(outputTableName), numRows[inputStructureId], &outputStructureId);
	
	uint8_t *readBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	// std::queue<Linear_Scan_Block *> resultBuffer; //store projection and filtered tuples.
	std::vector<Linear_Scan_Block*> resultBuffer;//store projection and filtered tuples.
	DBGprint("table size %d, numRealRows %d\n", oblivStructureSizes[inputStructureId], numRows[inputStructureId]);
	PrefixSumOracle oracle(batchSize, epsilon);
	//DBGprint("create oracle\n");
	int tableCapacity = oblivStructureSizes[inputStructureId];
	//DBGprint("get structure size\n");
	float dpPrefixSum = 0;
	for (int i = 0; i < tableCapacity; i += batchSize)
	{
		//DBGprint("try to read %dth row\n", i);
		opBatchLinearScanBlock(inputStructureId, i, std::min(batchSize, tableCapacity - i), readBuffer, 0);

		//DBGprint("end read %dth batch\n", i);
		Linear_Scan_Block *readBufPointer = (Linear_Scan_Block *)readBuffer;
		uint32_t count = 0;
		//printRow((uint8_t*) readBufPointer, schemas[inputStructureId]);
		for (int j = 0; j < std::min(batchSize, tableCapacity - i); j++)
		{
			bool filterResult = filter((uint8_t *)readBufPointer->data, input_schema, c) == 1;

			Linear_Scan_Block *tmp = (Linear_Scan_Block *)malloc(BLOCK_DATA_SIZE);
			memset(tmp, DUMMY, BLOCK_DATA_SIZE);

			projection((uint8_t *)readBufPointer->data, (uint8_t *)readBufPointer->data, input_schema, output_schema, columnsToProjected);
			memcpy(tmp, readBufPointer, BLOCK_DATA_SIZE);
			ObliMov(filterResult, tmp->data, readBufPointer->data);
			resultBuffer.push_back(tmp);
			int new_count = count + 1;
			CMOV1(filterResult, count, new_count);

			readBufPointer++; //move to next tuple.
		}
		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), count);
		dpPrefixSum = oracle.getDPPrefixSum(i + batchSize);
		DBGprint("processed index %d,numRows[outputStructureId] %d, dpPrefixSum %f, resultBuffer size %d\n", std::min(i + batchSize - 1, tableCapacity), numRows[outputStructureId], dpPrefixSum, resultBuffer.size());
		
		// bitonic sort the buffer so that the real tuples to the front
		DBGprint("start bitonic sort size %d\n", resultBuffer.size());
		bitonic_sort_vector(resultBuffer, 0, resultBuffer.size());
		DBGprint("end bitonic sort\n");

		DBGprint("numrows %d, dpPrefixSum - batchSize %f\n", numRows[outputStructureId], dpPrefixSum - batchSize);


		//write back some result rows.
		int writeBackSize = dpPrefixSum - batchSize - numRows[outputStructureId];

		DBGprint("%d batch--output size %d, dpPrefixSum %f--find the %dth match\n", i / batchSize, numRows[outputStructureId], dpPrefixSum, numRows[outputStructureId]);
		if(writeBackSize > 0){
			// the write back size is obfuscated by DPPrefixSum and is ok to be leaked
			uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
			int index = 0;
			while (index < writeBackSize)
			{
				Linear_Scan_Block *writeBackRow = resultBuffer.front();
				resultBuffer.erase(resultBuffer.begin());
				memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
				index++;
				free(writeBackRow);
			}
			opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);
			numRows[outputStructureId] += writeBackSize;
			free(writeBackBatch);
		}

		
		int to_pop = resultBuffer.size() - batchSize * 2; 
		//we should truncate from tail.
		for(int i = 0; i < to_pop; i++){
			Linear_Scan_Block * dummy = resultBuffer.back();
			resultBuffer.pop_back();
			free(dummy);
		}
	}

	//If we reach the end of the input, pop all the remaining tuples in the working buffer to theoutput,
	//then write dummy tuples to the output till the output reaches size Y_N+batchSize
	//batched version
	int writeBackSize = resultBuffer.size();
	uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
	int index = 0;
	while (index < writeBackSize)
	{
		Linear_Scan_Block *writeBackRow = resultBuffer.front();
		resultBuffer.erase(resultBuffer.begin());
		memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
		index++;
		free(writeBackRow);
	}
	//DBGprint("Final cleanup start-- currently numRows %d\n", numRows[outputStructureId]);

	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);

	numRows[outputStructureId] += writeBackSize;
	free(writeBackBatch);
	//DBGprint("Final cleanup done-- currently numRows %d\n", numRows[outputStructureId]);

	//batched version
	float finalPrefixSum;

	finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[inputStructureId] / batchSize + 1) * batchSize);


	int dummySize = (int)finalPrefixSum + batchSize - numRows[outputStructureId];
	// the dummySize is obfuscated by DPPrefixSum and is ok to be leaked
	if(dummySize > 0){
		//DBGprint("finalPrefixSum %f, insert %d dummy rows\n", finalPrefixSum, dummySize);
		uint8_t *dummyBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * dummySize);
		memset(dummyBatch, DUMMY, BLOCK_DATA_SIZE * dummySize);
		opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], dummySize, dummyBatch, 1);
		free(dummyBatch);
	}


	//DBGprint("selectivity : %d / %d, padding size : %d\n", numRows[outputStructureId], oblivStructureSizes[inputStructureId], dummySize);
	//DBGprint("start update result size from %d to %d\n" ,oblivStructureSizes[outputStructureId], dummySize + numRows[outputStructureId]);
	oblivStructureSizes[outputStructureId] = dummySize + numRows[outputStructureId]; // oblivStructureSizes is capacity. numRows is number of real rows.
	ocall_updateStructureSize(outputStructureId, oblivStructureSizes[outputStructureId]);
	padding_counter += dummySize;
	free(readBuffer);
	return;
}

//sort based on group field.
void DOSortBasedGroupBy(char *tableName, char *outputTableName, std::vector<AggregateType> aggregateType, std::vector<int> afield, int gfield, int substrLen)
{

	int structureId = getTableId(tableName);
	size_t tableCapacity = getTableCapacity(structureId);
	bucketObliviousSort(structureId, std::vector<int>{gfield}, 1);

	//printTable(tableNames[structureId]);
	int sortedTableId = structureId;
	int groupValSize = substrLen;

	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *groupVal = (uint8_t *)malloc(groupValSize + 1);

	int outputStructureId = -1;
	Schema retSchema;

	retSchema.numFields = 2 + afield.size();
	retSchema.fieldOffsets[0] = 0;
	retSchema.fieldTypes[0] = CHAR;
	retSchema.fieldSizes[0] = 1;
	char *prefixName = "AggregatedValue_";
	for (int i = 1; i < afield.size() + 1; i++)
	{
		retSchema.fieldOffsets[i] = 1 + (i - 1) * 4;
		retSchema.fieldTypes[i] = INTEGER;
		retSchema.fieldSizes[i] = 4;
	}

	retSchema.fieldOffsets[1 + afield.size()] = 1 + afield.size() * 4;
	retSchema.fieldTypes[1 + afield.size()] = schemas[structureId].fieldTypes[gfield];
	retSchema.fieldSizes[1 + afield.size()] = groupValSize + 1;
	retSchema.fieldNames[1 + afield.size()] = schemas[structureId].fieldNames[schemas[structureId].fieldOffsets[gfield]];

	double epsilon = 1.0;
	int batchSize = 1024;
	PrefixSumOracle oracle(batchSize, epsilon);
	int out = createTable(&retSchema, outputTableName, strlen(outputTableName), tableCapacity + batchSize, &outputStructureId);
	DBGprint("sort groupby create return table\n");
	std::vector<Linear_Scan_Block *> resultBuffer;
	DBGprint("try to create groupstat vector, size %d\n", aggregateType.size());
	uint32_t groupStat[MAX_COLS] = {0};
	uint32_t groupStatNewGroup[MAX_COLS] = {0};

	uint32_t groupCount = 0;
	uint8_t *prev = (uint8_t *)malloc(groupValSize + 1);
	//opOneLinearScanBlock(sortedTableId, 0, (Linear_Scan_Block *)row, 0);
	//memcpy(prev, &row[schemas[structureId].fieldOffsets[gfield]], groupValSize);
	prev[groupValSize] = '\0';
	uint8_t *junk = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	for (int i = 0; i < tableCapacity; i += batchSize)
	{
		//read from sorted table!!!
		printf("start allocate buffer\n");
		uint8_t *readBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
		printf("start read batch\n");
		opBatchLinearScanBlock(sortedTableId, i, std::min(batchSize, (int)tableCapacity - i), readBuffer, 0);
		Linear_Scan_Block *readBufPointer = (Linear_Scan_Block *)readBuffer;
		printf("read batch success\n");
		uint32_t numOfGroupThisBatch = 0;
		for (int j = 0; j < std::min(batchSize, (int)tableCapacity - i); j++)
		{
			memcpy(row, readBufPointer, BLOCK_DATA_SIZE);
			//std::vector<int> aggrValVec(afield.size(), 0);
			int aggrValVec[MAX_COLS] = {0};
			memcpy(groupVal, &row[schemas[structureId].fieldOffsets[gfield]], groupValSize);
			groupVal[groupValSize] = '\0';
			for (int i = 0; i < afield.size(); i++)
			{
				memcpy(&aggrValVec[i], &row[schemas[structureId].fieldOffsets[afield[i]]], 4);
			}
			DBGprint("cmp (%s, %s) = %d \n", prev, groupVal, strcmp((char *)prev, (char *)groupVal));

			bool old_group = (strcmp((char *)prev, (char *)groupVal) == 0);
			
			//equal means current is not a new group val
			//DBGprint("old group, groupStat size %d, aggrValVec size %d\n", groupStat.size(), aggrValVec.size());
			uint32_t groupCount_old = groupCount + 1;
			uint32_t groupCount_new = 1;
			CMOV1(old_group, groupCount, groupCount_old);
			CMOV1(!old_group, groupCount, groupCount_new);
			for (int k = 0; k < afield.size(); k++)
			{
				// to simplify the in-enclave oblivious implementation, only support the SUM for the BDB2.
				// it is OK to support other aggregation type.
				groupStat[k] += aggrValVec[k];
			}

			//old group. we only write a dummy value to hide memory
			uint8_t *tmp = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			memset(tmp, DUMMY, BLOCK_DATA_SIZE);

			//real write
			uint8_t *tmp_real = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			memset(tmp_real, '0', BLOCK_DATA_SIZE);
			tmp_real[0] = 'a';
			for (int i = 1; i < afield.size() + 1; i++)
			{
				memcpy(&row[retSchema.fieldOffsets[i]], &groupStat[i - 1], 4);
			}

			memcpy(&tmp_real[retSchema.fieldOffsets[1 + afield.size()]], prev, groupValSize + 1);

			ObliMov(!old_group, tmp, tmp_real);
			resultBuffer.push_back((Linear_Scan_Block *)tmp);

			memset(groupStatNewGroup, 0 , MAX_COLS * sizeof(uint32_t));
			memcpy(prev, groupVal, groupValSize);
			for (int k = 0; k < afield.size(); k++)
			{
				int aggrVal = aggrValVec[k];
				groupStatNewGroup[k] = aggrVal;
			}
			ObliMov(!old_group, groupStat, groupStatNewGroup, MAX_COLS);
			//DBGprint("old group %d, numGroups %d\n", (int)old_group, (int)numOfGroupThisBatch);
			uint32_t newNumOfGroupThisBatch = numOfGroupThisBatch + 1;
			CMOV1(!old_group, numOfGroupThisBatch, newNumOfGroupThisBatch);
			readBufPointer++;
		}

		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), numOfGroupThisBatch);

		float dpPrefixSum = oracle.getDPPrefixSum(i + batchSize);

		// bitonic sort the buffer so that the real tuples to the front
		printf("start bitonic sort size %d\n", resultBuffer.size());
		bitonic_sort_vector(resultBuffer, 0, resultBuffer.size());
		printf("end bitonic sort\n");

		//free it when not necessary. Just in case write back phase meets out of memory fault
		free(readBuffer);


		uint32_t writeBackSize = std::min((uint32_t)dpPrefixSum - batchSize - numRows[outputStructureId], (uint32_t)resultBuffer.size());
		printf("before write back i=%d, write back size = %d, buffer size = %d\n", i, writeBackSize, resultBuffer.size());
		if (writeBackSize > 0)
		{
			uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
			int index = 0;
			while (index < writeBackSize)
			{
				//write from front because they are real tuples
				Linear_Scan_Block *writeBackRow = resultBuffer.front();
				resultBuffer.erase(resultBuffer.begin());
				memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
				index++;
				free(writeBackRow);
			}
			//printf("before op numRows %d\n", numRows[outputStructureId]);
			opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);
			//printf("after op\n");
			numRows[outputStructureId] += writeBackSize;
			free(writeBackBatch);
		}
		printf("end write back i=%d\n", i);

	
		int to_pop = resultBuffer.size() - batchSize * 2 ; 
		//we should truncate from tail.
		for(int i = 0; i < to_pop; i++){
			Linear_Scan_Block * dummy = resultBuffer.back();
			resultBuffer.pop_back();
			free(dummy); //release the memory.
		}
		printf("end pop dummy\n");
	}

	printf("before final write back\n");

	//final write all left result buffer into output table
	int writeBackSize = resultBuffer.size();
	uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
	int index = 0;
	while (index < writeBackSize)
	{
		Linear_Scan_Block *writeBackRow = resultBuffer.front();
		resultBuffer.erase(resultBuffer.begin());
		memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
		index++;
		free(writeBackRow);
	}
	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], writeBackSize, writeBackBatch, 1);
	numRows[outputStructureId] += writeBackSize;
	free(writeBackBatch);
	printf("end final write back\n");

	float finalPrefixSum;

	finalPrefixSum = oracle.getDPPrefixSum((oblivStructureSizes[structureId] / batchSize + 1) * batchSize);

	printf("before dummy write back\n");

	//write some dummy rows into output table
	int dummySize = (int)finalPrefixSum + batchSize - numRows[outputStructureId];
	uint8_t *dummyBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * dummySize);
	memset(dummyBatch, DUMMY, BLOCK_DATA_SIZE * dummySize);
	opBatchLinearScanBlock(outputStructureId, numRows[outputStructureId], dummySize, dummyBatch, 1);
	oblivStructureSizes[outputStructureId] = dummySize + numRows[outputStructureId]; // oblivStructureSizes is capacity. numRows is number of real rows.
	free(dummyBatch);
	padding_counter += dummySize;
	printf("end dummy write back\n");
	ocall_updateStructureSize(outputStructureId, oblivStructureSizes[outputStructureId]);
	DBGprint("structure id %d shrinks from %d down to %d, containing %d real tuples\n", outputStructureId, tableCapacity + batchSize, oblivStructureSizes[outputStructureId], numRows[outputStructureId]);

	free(row);
	//free(groupVal);
	free(prev);
	return;
}

/*
	* @param afield
	*            The columns over which we are computing an aggregate.
	* @param gfield
	*            The column over which we are grouping the result, or -1 if
	*            there is no grouping
	* @param aggregateType
	*            The aggregation operator(MIN, MAX ,SUM, AVG, COUNT) to use
	* @param substrLen
	*            Used for SELECT SUBSTR(sourceIP, 1, X), SUM(adRevenue) FROM uservisits GROUP BY SUBSTR(sourceIP, 1, X). If groupby integer, substrLen can be set as the number of bits of int
	*/
void DOHashBasedGroupBy(char *tableName, char *outputTableName, std::vector<AggregateType> aggregateType, std::vector<int> afield, int gfield, int substrLen)
{
	DBGprint("start hash groupby\n");
	int structureId = getTableId(tableName);
	DBGprint("print hash groupby input table schema. size of input %d\n", numRows[structureId]);
	//printSchema(schemas[structureId]);
	//printTable(tableName);
	size_t tableCapacity = getTableCapacity(structureId);
	int batchSize = 65536;
	//aggregation variables
	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE); //used for iterative reading row by row
	int groupValSize = substrLen;
	uint8_t *groupVal = (uint8_t *)malloc(groupValSize + 1);

	uint8_t *hashIn = (uint8_t *)malloc(groupValSize); //this could be made to fit different sizes if we wanted
	sgx_sha256_hash_t *hashOut = (sgx_sha256_hash_t *)malloc(256);
	uint8_t* aesOut = (uint8_t *)malloc(128);
	DBGprint("init done\n");
	//hyperloglog cardinality estimate

	//t is the priority queue size within the DPDistinctCount
	double t = 10000.0;
	//DBGprint("t in DPDC is %f\n", t);
	DPDistinctCount* set2 = new DPDistinctCount(t);
	//hyper log log is the previous distinct elements estimation algorithm. it is deprecated
	//Hyper_log_log* set = new Hyper_log_log();
	uint8_t *batchBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	for (size_t i = 0; i < tableCapacity; i += batchSize)
	{
		opBatchLinearScanBlock(structureId, i, std::min((int)(tableCapacity - i), batchSize), batchBuffer, 0);
		for (int j = 0; j < std::min(batchSize, (int)(tableCapacity - i)); j++)
		{
			memcpy(row, batchBuffer + j * BLOCK_DATA_SIZE, BLOCK_DATA_SIZE);
			memcpy(groupVal, &row[schemas[structureId].fieldOffsets[gfield]], groupValSize);
			if (row[0] == DUMMY)
			{
				continue;
			}
			if (schemas[structureId].fieldTypes[gfield] != TINYTEXT)
				memcpy(hashIn, groupVal, groupValSize);
			else
				strncpy((char *)hashIn, (char *)groupVal, groupValSize);

			sgx_sha256_msg(hashIn, groupValSize, hashOut);
			unsigned long index = 0;
			memcpy(&index, hashOut, 8);
			//DBGprint("PRF generated val : %u\n", index);
			//set->add(index);
			set2->add(index);
		}
	}
	//the estimate number of distinct groups is not accurate, so we have to add some extra space
	//the larger is the inputtable, the more accurate is the estimation
	
	//at most 110% bounded DP distinct elements estimation approximation
	int numDistinctGroups = set2->get_dp_distinct_count(); 
	DBGprint("ours estimate distinct groups : %d\n", numDistinctGroups);

	// DBGprint("HLL estimate distinct groups : %d\n", set->get_uniq_num());
	// numDistinctGroups = set->get_uniq_num();
	int numPasses = numDistinctGroups / MAX_GROUPS_IN_ENCLAVE + 1;
	delete (set2);

	//return table config
	int retNameLen = strlen(outputTableName);
	int retStructId = -1;
	Schema retSchema;

	retSchema.numFields = 2 + afield.size();
	retSchema.fieldOffsets[0] = 0;
	retSchema.fieldTypes[0] = CHAR;
	retSchema.fieldSizes[0] = 1;
	char *prefixName = "AggregatedValue_";
	for (int i = 1; i < afield.size() + 1; i++)
	{
		retSchema.fieldOffsets[i] = 1 + (i - 1) * 4;
		retSchema.fieldTypes[i] = INTEGER;
		retSchema.fieldSizes[i] = 4;
		//TODO add aggregated column name
	}

	retSchema.fieldOffsets[1 + afield.size()] = 1 + afield.size() * 4;
	retSchema.fieldTypes[1 + afield.size()] = schemas[structureId].fieldTypes[gfield];
	retSchema.fieldSizes[1 + afield.size()] = groupValSize + 1;
	retSchema.fieldNames[1 + afield.size()] = schemas[structureId].fieldNames[schemas[structureId].fieldOffsets[gfield]];

	int retNumOfRows = numPasses * MAX_GROUPS_IN_ENCLAVE; //padding to the worst case

	createTable(&retSchema, outputTableName, retNameLen, retNumOfRows, &retStructId);
	for (int k = 0; k < numPasses; k++)
	{
		DBGprint("start %dth pass\n", k);
		std::unordered_map<unsigned long long, std::vector<int>> groupStat;
		std::unordered_map<unsigned long long, int> groupCount;
		std::unordered_map<unsigned long long, uint8_t *> groups; //used to record the groupVal, for the final write back to return table
		unsigned long long index = 0;							  // used as the key of groups, groupStat and groupCount
		int numGroupsCurrentPass = 0;

		for (int i = 0; i < tableCapacity; i += batchSize) //iterate through the full table
		{

			//DBGprint("start processing %dth pass, %dth element\n", k, i);
			opBatchLinearScanBlock(structureId, i, std::min(batchSize, (int)tableCapacity - i), batchBuffer, 0);
			for (int j = 0; j < std::min(batchSize, (int)tableCapacity - i); j++)
			{

				memcpy(row, batchBuffer + j * BLOCK_DATA_SIZE, BLOCK_DATA_SIZE);
				if (row[0] == DUMMY)
				{
					continue;
				}
				memcpy(groupVal, &row[schemas[structureId].fieldOffsets[gfield]], groupValSize);
				groupVal[groupValSize] = '\0';
				std::vector<int> aggrValVec(afield.size(), 0);
				for (int i = 0; i < afield.size(); i++)
				{
					memcpy(&aggrValVec[i], &row[schemas[structureId].fieldOffsets[afield[i]]], 4);
				}
				//DBGprint("row : %s, groupVal : %s\n", row, groupVal);

				if (schemas[structureId].fieldTypes[gfield] != TINYTEXT)
					memcpy(hashIn, groupVal, groupValSize);
				else
					strncpy((char *)hashIn, (char *)groupVal, groupValSize);

				sgx_sha256_msg(hashIn, groupValSize, hashOut);
				memcpy(&index, hashOut, 8);

				if (index % numPasses != k)
				{
					//use this to determine whether we want to process this group in this pass.
					//If hash values of groupVal are uniformly distributed, for each pass, we should process nearly the same amount of groups.
					continue;
				}

				if (groupStat.find(index) != groupStat.end())
				{
					//met this groupVal before
					//DBGprint("old group : %s \n", groups[index]);

					groupCount[index]++;
					for (int i = 0; i < aggrValVec.size(); i++)
					{
						int aggrVal = aggrValVec[i];
						switch (aggregateType[i])
						{
						case SUM:
						{
							//DBGprint("SUM on %dth col. prev val %d\n", afield[i], groupStat[index][i]);
							groupStat[index][i] += aggrVal;
							//DBGprint("SUM on %dth col. cur val %d\n", afield[i], groupStat[index][i]);
						}
						break;
						case MAX:
						{
							groupStat[index][i] = std::max(groupStat[index][i], aggrVal);
						}
						break;
						case MIN:
						{
							groupStat[index][i] = std::min(groupStat[index][i], aggrVal);
						}
						break;
						case COUNT:
						{
							groupStat[index][i]++;
						}
						break;
						case AVG:
						{
							groupStat[index][i] += aggrVal;
						}
						break;
						}
					}
				}
				else
				{
					groupCount[index] = 1;
					groups[index] = (uint8_t *)malloc(groupValSize + 1);
					memcpy(groups[index], &row[schemas[structureId].fieldOffsets[gfield]], groupValSize);
					groups[index][groupValSize] = '\0';
					//DBGprint("new group : %s \n", groups[index]);
					numGroupsCurrentPass++; //update the number of distinct groups we have met in current pass
											//the first time to meet this groupVal. Add new entry to groupStat and groupCount
					for (int i = 0; i < aggrValVec.size(); i++)
					{
						int aggrVal = aggrValVec[i];
						switch (aggregateType[i])
						{
						case SUM:
						{
							groupStat[index].push_back(aggrVal);
							//DBGprint("NEW group : SUM on %dth col. prev val %d\n", afield[i], groupStat[index][i]);
						}
						break;
						case MAX:
						{
							groupStat[index].push_back(aggrVal);
						}
						break;
						case MIN:
						{
							groupStat[index].push_back(aggrVal);
						}
						break;
						case COUNT:
						{
							groupStat[index].push_back(1);
						}
						break;
						case AVG:
						{
							groupStat[index].push_back(aggrVal);
						}
						break;
						}
					}
				}
			}
		}

		int counter = 0;
		DBGprint("final write back\n");
		for (std::unordered_map<unsigned long long, std::vector<int>>::iterator it = groupStat.begin(); it != groupStat.end(); ++it)
		{
			for (int i = 0; i < afield.size(); i++)
			{
				if (aggregateType[i] == AVG)
				{
					groupStat[it->first][i] /= groupCount[it->first];
				}
			}

			//real write

			memset(row, '0', BLOCK_DATA_SIZE);
			row[0] = 'a';

			for (int i = 1; i < afield.size() + 1; i++)
			{
				memcpy(&row[retSchema.fieldOffsets[i]], &it->second[i - 1], 4);
			}
			memcpy(&row[retSchema.fieldOffsets[1 + afield.size()]], groups[it->first], groupValSize + 1);

			memcpy(batchBuffer + counter * BLOCK_DATA_SIZE, row, BLOCK_DATA_SIZE);
			counter++;
			free(groups[it->first]); //free malloc memories for storing groupVals.

			if (counter % batchSize == 0)
			{
				opBatchLinearScanBlock(retStructId, numRows[retStructId], batchSize, batchBuffer, 1);
				numRows[retStructId] += batchSize;
				counter = 0; //reset counter;
				memset(batchBuffer, '0', BLOCK_DATA_SIZE * batchSize);
			}
		}
		opBatchLinearScanBlock(retStructId, numRows[retStructId], counter, batchBuffer, 1);
		numRows[retStructId] += counter;

		int dummyBatchSize = MAX_GROUPS_IN_ENCLAVE - numGroupsCurrentPass;
		DBGprint("current pass numGroupsCurrentPas %d, numRows[output] %d, need to insert %d dummy rows\n", numGroupsCurrentPass, numRows[retStructId], dummyBatchSize);
		memset(batchBuffer, DUMMY, BLOCK_DATA_SIZE * batchSize);
		for (int m = 0; m < dummyBatchSize; m += batchSize)
		{
			opBatchLinearScanBlock(retStructId, MAX_GROUPS_IN_ENCLAVE * k + numGroupsCurrentPass + m, std::min(batchSize, dummyBatchSize - m), batchBuffer, 1);
		}
		padding_counter += MAX_GROUPS_IN_ENCLAVE - numGroupsCurrentPass;
	}

	printf("DO groupby number of distinct groups : %d, padding size : %d\n", numRows[retStructId], retNumOfRows - numRows[retStructId]);
	//printTable(outputTableName);
	//ocall_updateStructureSize(retStructId, numRows[retStructId]);
	free(batchBuffer);
	free(row);
	free(groupVal);
	free(hashIn);
	free(hashOut);
	return;
}

//with foreign key constraint, sort join may be faster
void DOSortJoinWithForeginKey(char *leftTableName, char *rightTableName, char *outputTableName, int joinColLeft, int joinColRight)
{
	//assume left table is primary and right table is foregin key.
	//assume join columns have the same offset in the tuple for simpler sorting on the concatenated table.
	//printTable(rightTableName);

	//reset to zero
	decryption_time = 0;
	encryption_time = 0;
	inner_memcpy_time = 0;
	untrusted_mem_copy_to_enclave_time = 0;
	enclave_mem_copy_untrusted_time = 0;
	process_time = 0; //real operator process time within enclave
	// uint64_t start = rdtsc();
	// uint64_t end = rdtsc();
	int leftStructureId = getTableId(leftTableName);
	int rightStructureId = getTableId(rightTableName);
	int concatTableId = -1;
	int returnJoinTableId = -1;
	int tableCapacity1 = oblivStructureSizes[leftStructureId];
	int tableCapacity2 = oblivStructureSizes[rightStructureId];

	char *realRetTableName = "JoinReturn";
	char *concatTableName = "concatTable";
	int batchSize = 8192;
	double epsilon = 1.02;

	uint8_t *batchBuffer = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *row1 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *row2 = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	memset(row2, DUMMY, BLOCK_DATA_SIZE);
	memset(row1, DUMMY, BLOCK_DATA_SIZE);
	int fOffset1 = schemas[leftStructureId].fieldOffsets[joinColLeft];
	int fOffset2 = schemas[rightStructureId].fieldOffsets[joinColRight];
	int primary = 1;								// primary table
	int foreign = 2;								// foreign table
	Schema rightSchema = schemas[rightStructureId]; //need the second schema sometimes

	//initialize the return table schema
	Schema retSchema;
	retSchema.numFields = schemas[leftStructureId].numFields + schemas[rightStructureId].numFields - 1; //duplicate first field(whether it's DUMMY), duplicate join col
	int shift = 0;
	for (int i = 0; i < schemas[leftStructureId].numFields; i++)
	{
		retSchema.fieldOffsets[i] = schemas[leftStructureId].fieldOffsets[i];
		retSchema.fieldSizes[i] = schemas[leftStructureId].fieldSizes[i];
		retSchema.fieldTypes[i] = schemas[leftStructureId].fieldTypes[i];
		retSchema.fieldNames[i] = schemas[leftStructureId].fieldNames[i];
		shift++;
	}
	for (int i = 1; i < rightSchema.numFields; i++)
	{
		retSchema.fieldOffsets[shift] = retSchema.fieldOffsets[shift - 1] + retSchema.fieldSizes[shift - 1];
		retSchema.fieldSizes[shift] = rightSchema.fieldSizes[i];
		retSchema.fieldTypes[shift] = rightSchema.fieldTypes[i];
		retSchema.fieldNames[shift] = rightSchema.fieldNames[i];
		shift++;
	}

	// add schema support for the primary/foreign row marker
	DBGprint("start constructing concatenated schema\n");
	Schema concatenatedTableSchema = schemas[leftStructureId];
	concatenatedTableSchema.numFields = schemas[leftStructureId].numFields + 1;
	concatenatedTableSchema.fieldOffsets[concatenatedTableSchema.numFields - 1] = BLOCK_DATA_SIZE - 8;
	concatenatedTableSchema.fieldSizes[concatenatedTableSchema.numFields - 1] = 4;
	concatenatedTableSchema.fieldTypes[concatenatedTableSchema.numFields - 1] = INTEGER;
	//concatenatedTableSchema.fieldNames[concatenatedTableSchema.numFields - 1] = "Primary/Foreign";
	DBGprint("end constructing concatenated schema\n");

	createTable(&concatenatedTableSchema, concatTableName, strlen(concatTableName), tableCapacity1 + tableCapacity2, &concatTableId);
	//we don't need the schema for the concated row
	//for implementation simplicity, we only support when the two table join fields have the same offset.
	memset(batchBuffer, 0, BLOCK_DATA_SIZE * batchSize);
	for (int i = 0; i < tableCapacity1; i += batchSize)
	{
		// DBGprint("left table read %d\n", i);
		opBatchLinearScanBlock(leftStructureId, i, std::min((int)(tableCapacity1 - i), batchSize), batchBuffer, 0);
		for (int j = 0; j < std::min(batchSize, (int)(tableCapacity1 - i)); j++)
		{
			memcpy(&batchBuffer[BLOCK_DATA_SIZE * (i * batchSize + j + 1) - 8], &primary, 4); //1 stands for primary key
																							  // int tmp = 0;
																							  // memcpy(&tmp, &batchBuffer[BLOCK_DATA_SIZE * (i * batchSize + j + 1) - 8], 4);
																							  // DBGprint("mark %d\n", tmp);
		}
		opBatchLinearScanBlock(concatTableId, i, std::min((int)(tableCapacity1 - i), batchSize), batchBuffer, 1);
		numRows[concatTableId] += std::min(batchSize, (int)(tableCapacity1 - i));
	}
	DBGprint("finish left table\n");
	//printTableById(concatTableId, concatenatedTableSchema);
	for (int i = 0; i < tableCapacity2; i += batchSize)
	{
		opBatchLinearScanBlock(rightStructureId, i, std::min((int)(tableCapacity2 - i), batchSize), batchBuffer, 0);
		for (int j = 0; j < std::min(batchSize, (int)(tableCapacity2 - i)); j++)
		{
			memcpy(&batchBuffer[BLOCK_DATA_SIZE * (i * batchSize + j + 1) - 8], &foreign, 4); //2 stands for foreign key
																							  // int tmp = 0;
																							  // memcpy(&tmp, &batchBuffer[BLOCK_DATA_SIZE * (i * batchSize + j + 1) - 8], 4);
																							  // DBGprint("mark %d\n", tmp);
		}
		opBatchLinearScanBlock(concatTableId, i + tableCapacity1, std::min((int)(tableCapacity2 - i), batchSize), batchBuffer, 1);
		numRows[concatTableId] += std::min(batchSize, (int)(tableCapacity2 - i));
	}
	DBGprint("finish right table\n");

	//printTableById(concatTableId, concatenatedTableSchema);

	DBGprint("concatenated table size %d\n", numRows[concatTableId]);

	//sort on the join column and the primary/foreign marker column to ensure that when join column is the same, the primary row is followed by foreign rows
	
	//replace with old obliDB sort for comparison.
	// memset(row, 0, BLOCK_DATA_SIZE);
	// memset(row1, 0, BLOCK_DATA_SIZE);
	// memset(row2, 0, BLOCK_DATA_SIZE);
	//bitonicSort(concatTableId, 0, tableCapacity1 + tableCapacity2, 0, row1, row2, std::vector<int>{joinColLeft, schemas[concatTableId].numFields - 1});
	//bucketObliviousSort is what we really use in DO sort merge join operator. bitonic sort is only used for performance comparison.
	//start = rdtsc();


	printf("start bucketObliviousSort\n");
	bucketObliviousSort(concatTableId, std::vector<int>{joinColLeft, schemas[concatTableId].numFields - 1}, 1);
	printf("end bucketObliviousSort\n");


	// end = rdtsc();
	// sort_time = end - start;
	// printf("sort time %llu\n", sort_time);
	
	
	
	//printTableById(concatTableId, concatenatedTableSchema);
	std::vector<Linear_Scan_Block *> resultBuffer; //store filtered tuples.
	PrefixSumOracle oracle(batchSize, epsilon);

	//we create a table of such size, but eventually we do not use that much.
	createTable(&retSchema, realRetTableName, strlen(realRetTableName), tableCapacity2 + batchSize, &returnJoinTableId);
	memset(batchBuffer, 0, BLOCK_DATA_SIZE * batchSize);
	// DBGprint("join table schema print\n");
	// printSchema(retSchema);
	// DBGprint("left table schema print\n");
	// printSchema(schemas[leftStructureId]);
	// DBGprint("right table schema print\n");
	// printSchema(schemas[rightStructureId]);
	for (int i = 0; i < tableCapacity1 + tableCapacity2; i += batchSize)
	{

		opBatchLinearScanBlock(concatTableId, i, std::min((int)(tableCapacity1 + tableCapacity2 - i), batchSize), batchBuffer, 0);
		uint32_t count = 0;
		// start = rdtsc();
		//DBGprint("i %d, batchSize %d\n", i, std::min((int)(tableCapacity1 + tableCapacity2 - i), batchSize));
		for (int j = 0; j < std::min((int)(tableCapacity1 + tableCapacity2 - i), batchSize); j++)
		{
			shift = getRowSize(&schemas[leftStructureId]); //minus 4 which is a column storing primary/foreign marker
			memcpy(row, batchBuffer + j * BLOCK_DATA_SIZE, BLOCK_DATA_SIZE);
			int rowMarker = 0;
			memcpy(&rowMarker, &row[BLOCK_DATA_SIZE - 8], 4);
			bool realFromTable1 = (rowMarker == primary) && (row[0] != DUMMY);
			bool realFromTable2 = (rowMarker == foreign) && (row[0] != DUMMY);
			ObliMov( realFromTable1, row1, row);
			ObliMov( realFromTable2, row2, row);

			// printRow(row1, schemas[leftStructureId]);
			// printRow(row2, schemas[rightStructureId]);
			bool real = (row[0] != DUMMY) && (row1[0] != DUMMY) && (row2[0] != DUMMY); // check if both rows are not dummies
			//check join match conditions
			bool match = real && (memcmp(&row1[schemas[leftStructureId].fieldOffsets[joinColLeft]], &row2[schemas[rightStructureId].fieldOffsets[joinColRight]], rightSchema.fieldSizes[joinColRight]) == 0);


			ObliMov(match, row, row1);
			for (int k = 1; k < schemas[rightStructureId].numFields; k++)
			{
				//DBGprint("constructing joined tuple. shift %d, right column index %d, offset %d, len %d\n", shift, k, schemas[rightStructureId].fieldOffsets[k], schemas[rightStructureId].fieldSizes[k]);
				memcpy(&row[shift], &row2[schemas[rightStructureId].fieldOffsets[k]], schemas[rightStructureId].fieldSizes[k]);
				shift += schemas[rightStructureId].fieldSizes[k];
			}
			//DBGprint("FIND MATCH during process %dth row in the concatenated table.\n", i + j);
			//printRow(row, retSchema);
			Linear_Scan_Block *tmp = (Linear_Scan_Block *)malloc(BLOCK_DATA_SIZE);
			memset(tmp, DUMMY, BLOCK_DATA_SIZE);
			// memcpy(tmp, row, BLOCK_DATA_SIZE);
			ObliMov(match, tmp->data, row);
			resultBuffer.push_back(tmp);
			uint32_t new_count = count + 1;
			CMOV1(match, count, new_count);

		}

		//bitonic sort the result buffer in enclave.
		DBGprint("start bitonic sort size %d\n", resultBuffer.size());
		bitonic_sort_vector(resultBuffer, 0, resultBuffer.size());
		DBGprint("end bitonic sort\n");

		//finish process current batch
		oracle.arriveNewInterval(getInterval(i + 1, i + batchSize), count);
		float dpPrefixSum = oracle.getDPPrefixSum(i + batchSize);
		// end = rdtsc();
		// process_time += end - start;

		int writeBackSize = dpPrefixSum - batchSize - numRows[returnJoinTableId];

		if (writeBackSize > 0)
		{
			uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
			int index = 0;
			while (index < writeBackSize)
			{
				Linear_Scan_Block *writeBackRow = resultBuffer.front();
				resultBuffer.erase(resultBuffer.begin());
				memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
				index++;
				free(writeBackRow);
			}
			opBatchLinearScanBlock(returnJoinTableId, numRows[returnJoinTableId], writeBackSize, writeBackBatch, 1);
			numRows[returnJoinTableId] += writeBackSize;
			free(writeBackBatch);
		}

		

		int to_pop = resultBuffer.size() - batchSize * 2; 
		//we should truncate from tail.
		for(int i = 0; i < to_pop; i++){
			Linear_Scan_Block * dummy = resultBuffer.back();
			resultBuffer.pop_back();
			free(dummy);
		}
	}
	free(batchBuffer);

	//write back the rest
	int writeBackSize = resultBuffer.size();
	uint8_t *writeBackBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * writeBackSize);
	int index = 0;
	while (index < writeBackSize)
	{
		Linear_Scan_Block *writeBackRow = resultBuffer.front();
		resultBuffer.erase(resultBuffer.begin());
		memcpy(writeBackBatch + BLOCK_DATA_SIZE * index, writeBackRow, BLOCK_DATA_SIZE);
		index++;
		free(writeBackRow);
	}

	opBatchLinearScanBlock(returnJoinTableId, numRows[returnJoinTableId], writeBackSize, writeBackBatch, 1);
	numRows[returnJoinTableId] += writeBackSize;
	free(writeBackBatch);
	DBGprint("final write back complete\n");

	//printTableById(returnJoinTableId, retSchema);

	float finalPrefixSum = oracle.getDPPrefixSum(((tableCapacity1 + tableCapacity2) / batchSize + 1) * batchSize);

	int dummySize = (int)finalPrefixSum + batchSize - numRows[returnJoinTableId];

	if(dummySize > 0){
		uint8_t *dummyBatch = (uint8_t *)malloc(BLOCK_DATA_SIZE * dummySize);
		memset(dummyBatch, DUMMY, BLOCK_DATA_SIZE * dummySize);
		printf("start final dummy writes, cur size %d, dummy batch size %d, capacity %d\n", numRows[returnJoinTableId], dummySize, oblivStructureSizes[returnJoinTableId]);
		//final DO dummy writes
		opBatchLinearScanBlock(returnJoinTableId, numRows[returnJoinTableId], dummySize, dummyBatch, 1);
		DBGprint("finish dummy writes\n");
		free(dummyBatch);
	}




	//ocall_updateStructureSize(returnJoinTableId, numRows[returnJoinTableId] +dummySize);
	padding_counter += dummySize;
	DBGprint("DOSortJoin rows(Following are rdtsc() values, not real time scale) - %d  - encryption %llu - decryption %llu - inner_memcpy %llu - untrusted_to_enclave_memory %llu - enclave_to_trusted_memory %llu -process time : %llu\n", numRows[leftStructureId], encryption_time, decryption_time, inner_memcpy_time, untrusted_mem_copy_to_enclave_time, enclave_mem_copy_untrusted_time, process_time);

	deleteTable(leftTableName);
	deleteTable(rightTableName);
	deleteTable(concatTableName); //save memory
								  //DBGprint("clean up buffers\n");
	free(row);
	free(row1);
	free(row2);

	printf("joined table num of rows : %d\n\n\n", numRows[getTableId("JoinReturn")]);
	return;
}



//params are easy to understand.
void FOHashJoin(char *leftTableName, char *rightTableName, char *outputTableName, int joinColLeft, int joinColRight)
{
	//naive worst case join?
	int leftStructureId = getTableId(leftTableName);
	int rightStructureId = getTableId(rightTableName);
	size_t leftTableLength = getTableCapacity(leftStructureId);
	size_t rightTableLength = getTableCapacity(rightStructureId);
	int joinColSize = schemas[leftStructureId].fieldSizes[joinColLeft];
	int joinColType = schemas[leftStructureId].fieldTypes[joinColLeft];
	int realRetStructId = -1;

	Schema rightSchema = schemas[rightStructureId]; //need the second schema sometimes

	//initialize the return table schema
	Schema retSchema;
	retSchema.numFields = schemas[leftStructureId].numFields + schemas[rightStructureId].numFields - 2; //duplicate first field(whether it's DUMMY), duplicate join col
	int shift = 0;
	for (int i = 0; i < schemas[leftStructureId].numFields; i++)
	{
		retSchema.fieldOffsets[i] = schemas[leftStructureId].fieldOffsets[i];
		retSchema.fieldSizes[i] = schemas[leftStructureId].fieldSizes[i];
		retSchema.fieldTypes[i] = schemas[leftStructureId].fieldTypes[i];
		retSchema.fieldNames[i] = schemas[leftStructureId].fieldNames[i];
		shift++;
	}
	for (int i = 1; i < rightSchema.numFields; i++)
	{
		if (i == joinColRight)
			continue;
		retSchema.fieldOffsets[shift] = retSchema.fieldOffsets[shift - 1] + retSchema.fieldSizes[shift - 1];
		retSchema.fieldSizes[shift] = rightSchema.fieldSizes[i];
		retSchema.fieldTypes[shift] = rightSchema.fieldTypes[i];
		retSchema.fieldNames[shift] = rightSchema.fieldNames[i];
		shift++;
	}

	// in Q3, the join output cardinality is very small, which causes a lot of dummy I/O with untrusted memory.
	size_t retTableLength = std::max(leftTableLength * rightTableLength / JOIN_ROWS_IN_ENCLAVE, leftTableLength * 100); //full obliviousness needs worst case padding

	createTable(&retSchema, outputTableName, strlen(outputTableName), retTableLength, &realRetStructId);

	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *joinedRow = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	uint8_t *hashIn = (uint8_t *)malloc(joinColSize);
	sgx_sha256_hash_t *hashOut = (sgx_sha256_hash_t *)malloc(256);
	unsigned long index = 0;
	int insertionCounter = 0;
	int dummyCounter = 0;
	for (int i = 0; i < leftTableLength; i += JOIN_ROWS_IN_ENCLAVE)
	{
		std::unordered_map<unsigned long, std::vector<uint8_t *>> leftTablePartialMap;
		DBGprint("JOIN %dth pass\n", i / (JOIN_ROWS_IN_ENCLAVE));
		for (int j = 0; j < JOIN_ROWS_IN_ENCLAVE && i + j < leftTableLength; j++)
		{

			opOneLinearScanBlock(leftStructureId, i + j, (Linear_Scan_Block *)row, 0);
			if (row[0] == DUMMY)
				continue; //skip dummy rows
			//DBGprint("load %dth row in left table into hashtable : %s, %s \n", i+j, row, &row[retSchema.fieldOffsets[2]]);
			if (joinColType != TINYTEXT)
				memcpy(hashIn, &row[retSchema.fieldOffsets[joinColLeft]], retSchema.fieldSizes[joinColLeft]);
			else
				strncpy((char *)hashIn, (char *)&row[retSchema.fieldOffsets[joinColLeft]], retSchema.fieldSizes[joinColLeft]);

			sgx_sha256_msg(hashIn, retSchema.fieldSizes[joinColLeft], hashOut);
			memcpy(&index, hashOut, 4);

			uint8_t *tmp = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			memcpy(tmp, row, BLOCK_DATA_SIZE);
			if (leftTablePartialMap.find(index) != leftTablePartialMap.end())
			{
				leftTablePartialMap[index].push_back(tmp);
			}
			else
			{
				leftTablePartialMap[index] = std::vector<uint8_t *>{tmp};
			}
		}
		DBGprint("done hashtable for left table\n");
		//iterate through all the right table and find some match cases with left hash table in enclave.
		for (int k = 0; k < rightTableLength; k++)
		{
			//	DBGprint("%dth iteration, start processing %dth element in right table\n",i, k);
			opOneLinearScanBlock(rightStructureId, k, (Linear_Scan_Block *)row, 0);
			if (row[0] == DUMMY)
				continue; //skip dummy rows

			if (joinColType != TINYTEXT)
				memcpy(hashIn, &row[rightSchema.fieldOffsets[joinColRight]], rightSchema.fieldSizes[joinColRight]);
			else
				strncpy((char *)hashIn, (char *)&row[rightSchema.fieldOffsets[joinColRight]], rightSchema.fieldSizes[joinColRight]);

			sgx_sha256_msg(hashIn, rightSchema.fieldSizes[joinColRight], hashOut);
			memcpy(&index, hashOut, 4);

			if (leftTablePartialMap.find(index) != leftTablePartialMap.end())
			{
				for (int m = 0; m < leftTablePartialMap[index].size(); m++)
				{
					if (memcmp(&row[rightSchema.fieldOffsets[joinColRight]], &leftTablePartialMap[index][m][retSchema.fieldOffsets[joinColLeft]], retSchema.fieldSizes[joinColLeft]) == 0)
					{
						//a match case
						//DBGprint("find %dth match from left table : %s, %s\n", numRows[realRetStructId], &leftTablePartialMap[index][m][retSchema.fieldOffsets[1]], &leftTablePartialMap[index][m][retSchema.fieldOffsets[2]]);
						memcpy(joinedRow, leftTablePartialMap[index][m], BLOCK_DATA_SIZE);
						shift = getRowSize(&schemas[leftStructureId]);
						for (int k = 1; k < rightSchema.numFields; k++)
						{
							if (k == joinColRight)
								continue;

							memcpy(&joinedRow[shift], &row[rightSchema.fieldOffsets[k]], rightSchema.fieldSizes[k]);
							shift += rightSchema.fieldSizes[k];
						}

						opOneLinearScanBlock(realRetStructId, insertionCounter, (Linear_Scan_Block *)joinedRow, 1);
						insertionCounter++;
						numRows[realRetStructId]++;
					}
				}
			}
			else
			{
				memset(joinedRow, DUMMY, BLOCK_DATA_SIZE);
				//opOneLinearScanBlock(realRetStructId, insertionCounter, (Linear_Scan_Block *)joinedRow, 1);
				//insertionCounter++;
				dummyCounter++;
			}
			//DBGprint("insert counter %d out of%d", insertionCounter, retTableLength);
		}

		for (std::unordered_map<unsigned long, std::vector<uint8_t *>>::iterator it = leftTablePartialMap.begin(); it != leftTablePartialMap.end(); ++it)
		{
			for (int j = 0; j < it->second.size(); j++)
			{
				free(it->second[j]);
			}
		}
	}

	ocall_updateStructureSize(realRetStructId, numRows[realRetStructId] + 100);

	free(hashIn);
	free(hashOut);
	free(row);
	free(joinedRow);

	return;
}

// X ~ Laplace(mu, b). In DP mechanism, b is set as sensitivity / epsilon
double getLaplaceNoise(double b)
{
	int32_t val1, val2;
	sgx_read_rand((unsigned char *)&val1, 4);
	sgx_read_rand((unsigned char *)&val2, 4);
	//val1 = rand();
	//val2 = rand();
	double x = ((double)abs(val1) / RAND_MAX);
	double y = ((double)abs(val2) / RAND_MAX);
	if (x <= 0.5)
	{
		//DBGprint("laplace x %f, y %f, val1 %d, val2%d, noise %f\n",x , y, val1, val2, -b * log(1.0 - y));
		return -b * log(1.0 - y);
	}
	else
	{
		//DBGprint("laplace x %f, y %f, val1 %d, val2%d, noise %f\n",x , y, val1, val2, b * log(y));
		return b * log(y);
	}
}

extern int32_t getLowerBound(Interval in)
{
	int32_t res = in >> 32;
	return res;
}

extern int32_t getUpperBound(Interval in)
{
	int64_t tmp = (in << 32);
	int32_t res = tmp >> 32;
	return res;
}

extern int64_t getInterval(int32_t left, int32_t right)
{
	int64_t res = left;
	res = (res << 32) + right;
	return res;
}

int greatestPowerOfTwoLessThan(int n)
{
	int k = 1;
	while (k > 0 && k < n)
	{
		k = k << 1;
	}
	return k >> 1;
}

void bitonicSort(int tableId, int startIndex, int size, int flipped, uint8_t *row1, uint8_t *row2, std::vector<int> sortColIndex)
{
	if (size <= 1)
	{
		return;
	}
	else if (size < BITONIC_SORT_BIN)
	{
		uint8_t *workingSpace = (uint8_t *)malloc(size * BLOCK_DATA_SIZE);
		//copy all the needed rows into the working memory

		opBatchLinearScanBlock(tableId, startIndex, size, workingSpace, 0);

		smallBitonicSort(tableId, workingSpace, 0, size, flipped, sortColIndex);

		//write back to the table
		opBatchLinearScanBlock(tableId, startIndex, size, workingSpace, 1);


		free(workingSpace);
	}
	else
	{
		int mid = greatestPowerOfTwoLessThan(size);
		bitonicSort(tableId, startIndex, mid, 1, row1, row2, sortColIndex);
		bitonicSort(tableId, startIndex + (mid), size - mid, 0, row1, row2, sortColIndex);
		bitonicMerge(tableId, startIndex, size, flipped, row1, row2, sortColIndex);
	}
}

void bitonicMerge(int tableId, int startIndex, int size, int flipped, uint8_t *row1, uint8_t *row2, std::vector<int> sortColIndex)
{


	if (size == 1)
	{
		return;
	}
	else if (size < BITONIC_SORT_BIN)
	{
		uint8_t *workingSpace = (uint8_t *)malloc(size * BLOCK_DATA_SIZE);
		//copy all the needed rows into the working memory

		opBatchLinearScanBlock(tableId, startIndex, size, workingSpace, 0);

		smallBitonicMerge(tableId, workingSpace, 0, size, flipped, sortColIndex);

		//write back to the table
		opBatchLinearScanBlock(tableId, startIndex, size, workingSpace, 1);



		free(workingSpace);
	}
	else
	{
		int batchSize = 16384;
		uint8_t *workingSpace1 = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);
		uint8_t *workingSpace2 = (uint8_t *)malloc(BLOCK_DATA_SIZE * batchSize);

		std::vector<int> sortColOffset;
		std::vector<int> sortColLen;
		std::vector<DB_Type> sortColType;
		for (int i = 0; i < sortColIndex.size(); i++)
		{
			sortColOffset.push_back(schemas[tableId].fieldOffsets[sortColIndex[i]]);
			sortColLen.push_back(schemas[tableId].fieldSizes[sortColIndex[i]]);
			sortColType.push_back(schemas[tableId].fieldTypes[sortColIndex[i]]);
		}

		int swap = 0;
		int mid = greatestPowerOfTwoLessThan(size);

		for (int i = 0; i < size - mid; i += batchSize)
		{
			opBatchLinearScanBlock(tableId, startIndex +i, std::min(batchSize, size - mid -i), workingSpace1, 0);
			opBatchLinearScanBlock(tableId, startIndex + mid + i, std::min(batchSize, size - mid -i), workingSpace2, 0);

			for(int j = 0; j < batchSize; j++){
				if(cmpHelper(workingSpace1 + j * BLOCK_DATA_SIZE, workingSpace2 + j* BLOCK_DATA_SIZE, sortColOffset, sortColLen, sortColType, (flipped == 1))){
					swapRow(workingSpace1 + j* BLOCK_DATA_SIZE, workingSpace2 + j* BLOCK_DATA_SIZE);
				}
			}
			opBatchLinearScanBlock(tableId, startIndex +i, std::min(batchSize, size - mid -i), workingSpace1, 1);
			opBatchLinearScanBlock(tableId, startIndex + mid + i, std::min(batchSize, size - mid -i), workingSpace2, 1);

		}
		free(workingSpace1);
		free(workingSpace2);
		bitonicMerge(tableId, startIndex, mid, flipped, row1, row2, sortColIndex);
		bitonicMerge(tableId, startIndex + mid, size - mid, flipped, row1, row2, sortColIndex);
	}
}

void smallBitonicSort(int tableId, uint8_t *bothTables, int startIndex, int size, int flipped, std::vector<int> sortColIndex)
{
	if (size <= 1)
	{
		return;
	}
	else
	{
		int mid = greatestPowerOfTwoLessThan(size);
		smallBitonicSort(tableId, bothTables, startIndex, mid, 1,  sortColIndex);
		smallBitonicSort(tableId, bothTables, startIndex + mid, size - mid, 0,  sortColIndex);
		smallBitonicMerge(tableId, bothTables, startIndex, size, flipped, sortColIndex);
	}
}

void smallBitonicMerge(int tableId, uint8_t *bothTables, int startIndex, int size, int flipped, std::vector<int> sortColIndex)
{
	if (size == 1)
	{
		return;
	}
	else
	{
		std::vector<int> sortColOffset;
		std::vector<int> sortColLen;
		std::vector<DB_Type> sortColType;
		for (int i = 0; i < sortColIndex.size(); i++)
		{
			sortColOffset.push_back(schemas[tableId].fieldOffsets[sortColIndex[i]]);
			sortColLen.push_back(schemas[tableId].fieldSizes[sortColIndex[i]]);
			sortColType.push_back(schemas[tableId].fieldTypes[sortColIndex[i]]);
		}

		int swap = 0;
		int mid = greatestPowerOfTwoLessThan(size);
		for (int i = 0; i < size - mid; i++)
		{
			if(cmpHelper(&bothTables[(startIndex + i) * (BLOCK_DATA_SIZE)],  &bothTables[(startIndex + mid + i) * (BLOCK_DATA_SIZE)], 
						sortColOffset, sortColLen, sortColType, (flipped == 1) )){
							swapRow(&bothTables[(startIndex + i) * (BLOCK_DATA_SIZE)], &bothTables[(startIndex + mid + i) * (BLOCK_DATA_SIZE)]);
						}
		}
		smallBitonicMerge(tableId, bothTables, startIndex, mid, flipped, sortColIndex);
		smallBitonicMerge(tableId, bothTables, startIndex + mid, size - mid, flipped, sortColIndex);
	}
}