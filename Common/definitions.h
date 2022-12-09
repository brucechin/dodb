#ifndef DEFS
#define DEFS

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"


#define BLOCK_DATA_SIZE 768

//database parameters
#define NUM_STRUCTURES 1500 //number of tables supported
#define MAX_COLS 15
#define MAX_CONDITIONS 3 //number of ORs allowed in one clause of a condition
#define JOIN_ROWS_IN_ENCLAVE 50000
#define ROWS_IN_ENCLAVE_JOIN 50000
#define MAX_GROUPS_IN_ENCLAVE 400000
#define BIN_SIZE 100000
#define BITONIC_SORT_BIN 100000
typedef struct{
	uint8_t data[BLOCK_DATA_SIZE];
} Linear_Scan_Block;

typedef struct{
	uint8_t ciphertext[sizeof(Linear_Scan_Block)];
	uint8_t macTag[16]; //16 bytes
	uint8_t iv[12]; //12 bytes
} Encrypted_Linear_Scan_Block;

typedef enum _DB_TYPE{
	INTEGER, //4 bytes
	TINYTEXT, //255 bytes
	CHAR, //1 byte
} DB_Type;

typedef struct{
	int numFields;
	int fieldOffsets[MAX_COLS];
	int fieldSizes[MAX_COLS];
	DB_Type fieldTypes[MAX_COLS];
	char* fieldNames[MAX_COLS];
} Schema;

//conditions will be in CNF form (product of sums)
typedef struct Condition Condition;
struct Condition{
	int numClauses;
	int fieldIndex[MAX_CONDITIONS];
	int conditionType[MAX_CONDITIONS]; //only support equality for non-integer types
	uint8_t *values[MAX_CONDITIONS];
	Condition *nextCondition;
};
typedef enum _ConditionType{
	LESS = 0,
	EQUAL = 1,
	GREATER = 2,
	GREATEROREQUAL = 3,
	LESSOREQUAL = 4,
	NOTEQUAL = 5
}ConditionType;

typedef enum _AggregateType{
	COUNT,
	SUM,
	MIN,
	MAX,
	AVG
}AggregateType;

//first as lower bound, second as seconder bound for the interval : [first, second]
typedef int64_t Interval;


int getDBTypeSize(DB_Type type);
int getRowSize(Schema *schema);
#endif
