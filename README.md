# Differentially Oblivious Database

## How to get the Big Data Benchmark data
You can retrieve The small version of BDB dataset from https://github.com/SabaEskandarian/ObliDB repo

<!-- these are old instructions -->
<!-- 
## Run in Simulation Mode
```bash
mkdir build
cd build
cmake ..
make
wget https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/rankings.csv
wget https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/uservisits.csv
./App rankings.csv uservisits.csv 350000 350000
```

## Run in Hardware Mode
```bash
mkdir build
cd build
cmake -DSGX_HW=ON -DSGX_MODE=PreRelease ..
make
wget https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/rankings.csv
wget https://raw.githubusercontent.com/SabaEskandarian/ObliDB/master/uservisits.csv
./App rankings.csv uservisits.csv 350000 350000
``` -->

<!-- here are new instructions -->

## Benchmark in Simulation Mode(64GB memory required)
```bash
cd benchmark 
python3 datasetGenerator.py
cd ..
mkdir build
cp auto-test.sh build/
cd build
sh auto-test.sh
cd ../benchmark
python3 draw.py
```
