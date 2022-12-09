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

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <queue>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <list>
#include <cstring>
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "definitions.h"

#ifdef DEBUG
#define DBGprint(...) printf(__VA_ARGS__)
#else
#define DBGprint(...)
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

#define DUMMY '\0'
#define NULLCHAR '\1'
	void printf(const char *fmt, ...);
	//key for reading/writing to oblivious data structures
	extern sgx_aes_gcm_128bit_key_t *obliv_key;
	//for keeping track of structures, should reflect the structures held by the untrusted app;
	extern size_t oblivStructureSizes[NUM_STRUCTURES]; //actual size
	//specific to database application, hidden from app
	extern Schema schemas[NUM_STRUCTURES];
	extern char *tableNames[NUM_STRUCTURES];
	extern uint32_t numRows[NUM_STRUCTURES];
	extern void printPaddingCounter();
	extern void bucketObliviousSort(int inputStructureId, std::vector<int> sortColIndex, bool ascendant);
	extern void bucketSort(int structureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant);
	extern void swapRow(uint8_t *a, uint8_t *b);
	extern bool cmpHelper(uint8_t *a, uint8_t *b, std::vector<int> offsets, std::vector<int> lens, std::vector<DB_Type> types, bool asc);
	extern bool isTagetBitOne(int input, int index);
	extern void mergeSplitHelper(uint8_t *inputBuffer, int outputStructureId0, int outputStructureId1, int iter);
	extern void mergeSplit(int inputStructureId0, int inputStructureId1, int outputStructureId0, int outputStructureId1, int iter);
	extern void padWithDummy(int structureId, int startIndex);
	extern void kWayMergeSort(std::vector<int> structureIdVec, int outputStructureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant);
	extern void checkFinalSortCorrectness(int outputStructureId, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant);
	extern int partition(uint8_t *arr, int low, int high, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant);
	extern void quickSort(uint8_t *arr, int low, int high, std::vector<int> sortColOffset, std::vector<int> sortColLen, std::vector<DB_Type> sortColType, bool ascendant);
	extern int opOneLinearScanBlock(int structureId, int index, Linear_Scan_Block *block, int write);
	extern int encryptBlock(void *ct, void *pt);
	extern int decryptBlock(void *ct, void *pt);
	//en/de-crypt by index functions are not usable anymore
	// extern int decryptBlockByIndex(int ciphertextIndex, int plaintextIndex);
	// extern int encryptBlockByIndex(int ciphertextIndex, int plaintextIndex);

	extern int encryptBlockBatch(int ciphertextIndexStart, int plaintextIndexStart, int batchSize);
	extern int decryptBlockBatch(int ciphertextIndexStart, int plaintextIndexStart, int batchSize);

	extern int getNextStructureId();
	extern sgx_status_t keyInit();
	extern sgx_status_t initStructure(size_t size, int *structureId);
	extern sgx_status_t freeStructure(int structureId);

	// not all of them are implemented in Enclave.cpp
	extern int incrementNumRows(int structureId);
	extern int setNumRows(int structureId, int numRow);
	extern int getNumRows(int structureId);
	extern int createTable(Schema *schema, char *tableName, int nameLen, int numberOfRows, int *structureId);
	extern int getTableId(char *tableName);
	extern int printTable(char *tableName);

	extern int printTableById(int structureId, Schema schema);
	extern int printRow(uint8_t *row, Schema schema);

	extern Schema getTableSchema(char *tableName);
	extern int deleteTable(char *tableName);
	extern int Q1(char *tableName, Condition c);
	extern int DOQ1(char *tableName, Condition c);
	extern int DOSortBasedQ2(char *tableName, Condition c);
	extern int DOHashBasedQ2(char *tableName, Condition c);
	extern int DOFilterMicrobenchmark(char *tableName, Condition c);
	extern int DOProjectMicrobenchmark(char *tableName);
	extern int DOSortJoinMicrobenchmark();
	extern int Q3();

	extern void orderby(char *tableName, int *sortColIndex, int numSortCols, int ascendant, int limitSize, int algorithm);

	extern int filter(uint8_t *row, Schema s, Condition c);
	extern void projection(uint8_t *input, uint8_t *output, Schema input_schema, Schema output_schema, int *columnsToProjected);

	extern void DOProject(int inputStructureId, char *outputTableName, Schema input_schema, Schema output_schema, int *columnsToProjected);
	extern void DOFilter(int inputStructureId, char *outputTableName, Condition c);

	extern void FOProjectWithFilter(int inputStructureId, char *outputTableName, Condition c, Schema input_schema, Schema output_schema, int *columnsToProjected);
	extern void DOProjectWithFilter(int inputStructureId, char *outputTableName, Condition c, Schema input_schema, Schema output_schema, int *columnsToProjected);

	extern void DOSortBasedGroupBy(char *tableName, char *outputTableName, std::vector<AggregateType> aggregateType, std::vector<int> afield, int gfield, int substrLen);
	extern void DOHashBasedGroupBy(char *tableName, char *outputTableName, std::vector<AggregateType> aggregateType, std::vector<int> afield, int gfield, int substrLen);
	extern void FOHashJoin(char *leftTableName, char *rightTableName, char *outputTableName, int joinColLeft, int joinColRight);
	extern void DOSortJoinWithForeginKey(char *leftTableName, char *rightTableName, char *outputTableName, int joinColLeft, int joinColRight);
	extern int DPPrefixSumMicrobenchmark(int times);

	// X ~ Laplace(mu, b). In DP mechanism, b is set as sensitivity / epsilon
	extern double getLaplaceNoise(double b);
	extern int32_t getLowerBound(Interval in);
	extern int32_t getUpperBound(Interval in);
	extern int64_t getInterval(int32_t left, int32_t right);

	extern int greatestPowerOfTwoLessThan(int n);
	extern void bitonicSort(int tableId, int startIndex, int size, int flipped, uint8_t *row1, uint8_t *row2, std::vector<int> sortColIndex);
	extern void bitonicMerge(int tableId, int startIndex, int size, int flipped, uint8_t *row1, uint8_t *row2, std::vector<int> sortColIndex);
	extern void smallBitonicSort(int tableId, uint8_t *bothTables, int startIndex, int size, int flipped, std::vector<int> sortColIndex);
	extern void smallBitonicMerge(int tableId, uint8_t *bothTables, int startIndex, int size, int flipped, std::vector<int> sortColIndex);

	void print_queue(std::priority_queue<double> q)
	{
		while (!q.empty())
		{
			printf("%f, ", q.top());
			q.pop();
		}
	}
	class DPDistinctCount
	{
	private:
		//min priority queue
		std::priority_queue<double> q;
		std::unordered_set<double> set;
		double t;
		double delta = 0.000001;
		int duplicates = 0;

	public:
		DPDistinctCount(double t_)
		{
			t = t_;
			//DBGprint("t is %f\n", t);
		}
		void add(unsigned int x)
		{
			double y = (static_cast<double>(x) / UINT_MAX);
			//DBGprint("PRF [0,1] %f\n", y);
			if (q.size() < t)
			{
				if (set.find(y) == set.end())
				{
					q.push(y);
					set.insert(y);
				}
				else
				{
					//DBGprint("p1 duplicates\n");
					duplicates++;
				}
			}
			else if (y < q.top())
			{

				//print_queue(q);
				if (set.find(y) == set.end())
				{
					double tmp = q.top();
					set.erase(tmp);
					q.pop();
					q.push(y);
					set.insert(y);
				}
				else
				{
					//DBGprint("p2 duplicates\n");
					duplicates++;
				}
			}
			else{

			}
		}
		double get_dp_distinct_count()
		{
			q.pop(); //pop the one last inserted
			//print_queue(q);
			double v = q.top();
			//DBGprint("distinct count t %f, v %f, q size %d, num duplicates %d\n", t, v, q.size(), duplicates);
			return 	1.075 * (double)t/v + getLaplaceNoise(0.02 * ((double)t/v) / log(3/delta)); 

		}
	};

	struct HeapNode
	{
		uint8_t *data; //memory region len is BLOCK_DATA_SIZE
		int bucket;	   // indicate which bucket it originates from
		int index;	   // index of the bucket from which the element is taken
	};

	class Heap
	{
		HeapNode *harr; // pointer to array of elements in heap
		int heap_size;	// size of min heap
		std::vector<DB_Type> type;
		std::vector<int> cmpColOffset;
		std::vector<int> cmpColLen;
		bool ascendant;
		int batchSize; //read from untrusted memory by batching

	public:
		// Constructor: creates a min heap of given size
		Heap(HeapNode a[], int size, int bs, std::vector<int> colOffset, std::vector<int> colLen, std::vector<DB_Type> t, bool asc)
		{
			heap_size = size;
			harr = a; // store address of array
			int i = (heap_size - 1) / 2;
			cmpColOffset = colOffset;
			cmpColLen = colLen;
			ascendant = asc;
			type = t;
			batchSize = bs;
			while (i >= 0)
			{
				Heapify(i);
				i--;
			}
		}

		void Heapify(int i)
		{
			int l = left(i);
			int r = right(i);
			int target = i;

			if (l < heap_size && cmpHelper(harr[i].data + (harr[i].index % batchSize) * BLOCK_DATA_SIZE, harr[l].data + (harr[l].index % batchSize) * BLOCK_DATA_SIZE, cmpColOffset, cmpColLen, type, ascendant))
				target = l;
			if (r < heap_size && cmpHelper(harr[target].data + (harr[target].index % batchSize) * BLOCK_DATA_SIZE, harr[r].data + (harr[r].index % batchSize) * BLOCK_DATA_SIZE, cmpColOffset, cmpColLen, type, ascendant))
				target = r;
			if (target != i)
			{
				swapHeapNode(&harr[i], &harr[target]);
				Heapify(target);
			}
		}
		int left(int i)
		{
			return (2 * i + 1);
		}
		int right(int i)
		{
			return (2 * i + 2);
		}
		// A utility function to swap two elements
		void swapHeapNode(HeapNode *x, HeapNode *y)
		{
			HeapNode temp = *x;
			*x = *y;
			*y = temp;
		}

		HeapNode *getRoot()
		{
			return &harr[0];
		}
		int size()
		{
			return heap_size;
		}
		bool reduceSizeByOne()
		{
			free(harr[0].data);

			heap_size--;
			if (heap_size > 0)
			{
				//DBGprint("\n\n\nheap size minus one, current size %d\n\n\n", heap_size);
				harr[0] = harr[heap_size];
				Heapify(0);

				return true;
			}
			else
			{
				//DBGprint("\n\nall buckets processed!\n");
				//heap is empty. we have processed all the buckets.
				return false;
			}
		}
		void replaceRoot(HeapNode x)
		{
			harr[0] = x;
			Heapify(0);
		}
	};

	class PrefixSumOracle
	{
		int batchSize = 128;
		double epsilon = 1.02;
		int upperBoundBits = 32; // if the number of array is less than 2^20, we only need to process the least important 20 bits.
		std::unordered_map<Interval, int> pSumMap;
		std::unordered_map<Interval, float> noiseMap;
		//save true count and noise for each node
	public:
		PrefixSumOracle(int bs, double ep)
		{
			batchSize = bs;
			epsilon = ep;
		}
		int getPSum(Interval in)
		{
			
			int res = 0;
			if (pSumMap.find(in) == pSumMap.end())
			{
				int range = getUpperBound(in) - getLowerBound(in) + 1;
				Interval leftChild = getInterval(getLowerBound(in), getLowerBound(in) + range / 2 - 1);
				Interval rightChild = getInterval(getLowerBound(in) + range / 2, getUpperBound(in));
				res = getPSum(leftChild) + getPSum(rightChild);
				//this is not O(N). because pSumMap has all the leftChild during recursive call.
				//use [1,16] as example. [1,16] = [1,8] + [9, 12] + [13,14] + [15,15] + [16,16] = log2(16) + 1
			}
			else
			{
				res = pSumMap[in];
			}
			//DBGprint("get pSum[%d, %d] : %d\n", getLowerBound(in), getUpperBound(in), res);
			return res;
		}

		float getDPPrefixSum(int n)
		{
			float res = 0;
			int tmp = n & (0xFFFFFFFF << (int)log2(batchSize));
			//if input is 50000, we truncate it to the nearest batchSize * k, k is an integer. In this case, 50000 is truncated to 49920
			//DBGprint("Get prefixSum of %d, truncated to %d\n", n, tmp);

			for (int i = 0; i < upperBoundBits; i++)
			{
				bool flag = true;
				if (tmp & (1 << i))
				{ //the ith least important bit is 1
					Interval key = getInterval(tmp - pow(2, i) + 1, tmp);
					if (flag)
					{
						//for the first time, calculate the p-sum for key and store it into pSumMap. calculate once and use for multiple times.
						//delete all its children nodes, because we will only use it for calculating larger p-sum later.
						if (pSumMap.find(key) == pSumMap.end() && getUpperBound(key) > getLowerBound(key))
						{
							int key_psum = getPSum(key);
							pSumMap[key] = key_psum;
							noiseMap[key] = getLaplaceNoise(log2(getUpperBound(key) - getLowerBound(key)) / epsilon);
							//DBGprint("Add p-sum between [%d, %d], value is %d\n", getLowerBound(key), getUpperBound(key), pSumMap[key]);
							//this is easy to understand. If we have [15,16], we can delete [15,15] and [16,16] entry. We will only use [15,16] for calculating larger PrefixSum
							removeAllChildrenInterval(key);
							flag = false;
						}
					}

					res += pSumMap[key];
					//DBGprint("the %dth bit of %d is 1, [%d, %d] p-sum is %d\n", i, n, getLowerBound(key), getUpperBound(key), pSumMap[key]);
					tmp = ((tmp >> (i + 1)) << (i + 1)); // make the processed bits to zero
				}
			}
			//DBGprint("%d accurate prefixSum is %f, noise is %f\n", n, res, getLaplaceNoise(log2(n / batchSize) / epsilon));
			return res + getLaplaceNoise(log2(n / batchSize) / epsilon);
		}

		void removeAllChildrenInterval(Interval in)
		{
			//do not remove itself
			//DBGprint("before remove %d entries\n", pSumMap.size());

			int range = getUpperBound(in) - getLowerBound(in) + 1;
			Interval leftChild = getInterval(getLowerBound(in), getLowerBound(in) + range / 2 - 1);
			Interval rightChild = getInterval(getLowerBound(in) + range / 2, getUpperBound(in));
			if (pSumMap.find(leftChild) != pSumMap.end())
			{
				//DBGprint("find [%d, %d] to remove\n", getLowerBound(tmp), getUpperBound(tmp));
				pSumMap.erase(leftChild);
				noiseMap.erase(leftChild);
			}

			if (pSumMap.find(rightChild) != pSumMap.end())
			{
				//DBGprint("find [%d, %d] to remove\n", getLowerBound(tmp), getUpperBound(tmp));
				pSumMap.erase(rightChild);
				noiseMap.erase(rightChild);
			}

			range = getUpperBound(rightChild) - getLowerBound(rightChild) + 1;
			if (range > batchSize) //if smaller or equal to batchSize, it's obvious that it is a leaf node and has no children.
			{
				removeAllChildrenInterval(rightChild);
			}

			//DBGprint("Remove [%d, %d] children nodes, left %d entries\n", getLowerBound(in), getUpperBound(in), pSumMap.size());
			// for (auto it = pSumMap.begin(); it != pSumMap.end(); ++it)
			// 	DBGprint("[%d, %D] : %d\n", getLowerBound(it->first), getUpperBound(it->first), it->second);
		}

		void arriveNewInterval(Interval in, int count) //
		{
			pSumMap[in] = count;
			noiseMap[in] = getLaplaceNoise(log2(batchSize) / epsilon); //add laplce noise
																	   //DBGprint("arrive new item [%d, %d] -- %d, with laplace noise %f\n", getLowerBound(in), getUpperBound(in), count, noiseMap[in]);
		}
	};

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
