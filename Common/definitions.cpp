#include "definitions.h"
int getDBTypeSize(DB_Type type){
	int ret = 0;
	switch(type){
	case INTEGER:
		ret = 4;
		break;
	case TINYTEXT:
		ret = 255;
		break;
	case CHAR:
		ret = 1;
		break;
	}
	return ret;
}

int getRowSize(Schema *schema){
	int rowSize = 0;
	for(int i = 0; i < schema->numFields; i++){
		//if(schema->fieldOffsets[i] != rowSize) return -i;
		//if(i > 0 && schema->fieldOffsets[i] != schema->fieldOffsets[i-1]+schema->fieldSizes[i-1]) return -2;
		rowSize += schema->fieldSizes[i];
	}
	return rowSize;
}


