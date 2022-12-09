


# cp ../benchmark/data/rankings/10000/rankings_10000.csv .
# cp ../benchmark/data/rankings/100000/rankings_100000.csv .
# cp ../benchmark/data/rankings/1000000/rankings_1000000.csv .
# cp ../benchmark/data/rankings/10000000/rankings_10000000.csv .
# cp ../benchmark/data/uservisits/10000/uservisits_10000.csv .
# cp ../benchmark/data/uservisits/100000/uservisits_100000.csv .
# cp ../benchmark/data/uservisits/1000000/uservisits_1000000.csv .
# cp ../benchmark/data/uservisits/10000000/uservisits_10000000.csv .
# echo "benchmark data is ready"





# make clean
# # REMINDER : you need to manually set -DSGX_HW=ON to turn on the hardware mode
# cmake -DSGX_HW=ON -DSGX_MODE=PreRelease  -DPARALLEL=OFF ..
# make -j8 
for i in $(seq 1);
do
./App rankings_100000.csv uservisits_100000.csv 100000 300000 2| grep "-">> ../benchmark/usenix_singlethread_log.txt;
# ./App rankings_1000000.csv uservisits_1000000.csv 300000 900000 2| grep "-" >> ../benchmark/usenix_singlethread_log.txt # this line is only for do join benchmark
./App rankings_1000000.csv uservisits_1000000.csv 1000000 3000000 2| grep "-" >> ../benchmark/usenix_singlethread_log.txt
./App rankings_10000000.csv uservisits_10000000.csv 10000000 30000000 2| grep "-">> ../benchmark/usenix_singlethread_log.txt
done
# echo "single thread done"

# make clean
# # REMINDER : you need to manually set -DSGX_HW=ON to turn on the hardware mode
# cmake -DSGX_HW=ON -DSGX_MODE=PreRelease  -DPARALLEL=ON ..
# make -j8
# for i in $(seq 2);
# do
# ./App rankings_10000.csv uservisits_10000.csv 10000 30000 2| grep "-">> ../benchmark/hundun_parallel_log.txt;
# ./App rankings_100000.csv uservisits_100000.csv 100000 300000 2| grep "-">> ../benchmark/hundun_parallel_log.txt;
# ./App rankings_1000000.csv uservisits_1000000.csv 1000000 3000000 2| grep "-" >> ../benchmark/hundun_parallel_log.txt
# echo "parallel 1million done"
# ./App rankings_10000000.csv uservisits_10000000.csv 10000000 30000000 2| grep "-">> ../benchmark/hundun_parallel_log.txt
# echo "parallel 10million done"
# done
# echo "multi thread done"



# for sort based groupby VS hash based groupby
# make clean
# cmake .. -DPARALLEL=ON
# make -j8
# for i in $(seq 1);
# do
# ./App rankings_100000.csv uservisits_100000.csv 1000 100000 1| grep "running">> ../benchmark/hundun_parallel_log.txt
# ./App rankings_1000000.csv uservisits_1000000.csv 1000 200000 1| grep "running" >> ../benchmark/hundun_parallel_log.txt
# ./App rankings_1000000.csv uservisits_1000000.csv 1000 400000 1| grep "running" >> ../benchmark/hundun_parallel_log.txt
# ./App rankings_1000000.csv uservisits_1000000.csv 1000 800000 1| grep "running" >> ../benchmark/hundun_parallel_log.txt
# ./App rankings_1000000.csv uservisits_1000000.csv 1000 1600000 1| grep "running" >> ../benchmark/hundun_parallel_log.txt
# ./App rankings_10000000.csv uservisits_10000000.csv 1000 3200000 1| grep "running">> ../benchmark/hundun_parallel_log.txt
# ./App rankings_10000000.csv uservisits_10000000.csv 1000 6400000 1| grep "running">> ../benchmark/hundun_parallel_log.txt
# ./App rankings_10000000.csv uservisits_10000000.csv 1000 12800000 1| grep "running">> ../benchmark/hundun_parallel_log.txt
# done
# echo "multi thread done"



# below are scripts for auto benchmarking opaque and SparkSQL
# sudo docker run -it -m 64g --name new-opaque-bench -w /home/opaque/opaque ankurdave/opaque bash
# sudo docker start new-opaque-bench
# sudo docker cp ../benchmark/opaque/build.sbt new-opaque-bench:/home/opaque/opaque/
# sudo docker cp ../benchmark/opaque/Benchmark.scala new-opaque-bench:/home/opaque/opaque/src/main/scala/edu/berkeley/cs/rise/opaque/benchmark/
# sudo docker cp ../benchmark/data/rankings new-opaque-bench:/home/opaque/opaque/data/bdb/
# sudo docker cp ../benchmark/data/uservisits new-opaque-bench:/home/opaque/opaque/data/bdb/
# sudo docker exec -w /home/opaque/opaque new-opaque-bench build/sbt run edu.berkeley.cs.rise.opaque.benchmark.Benchmark 2>&1 >> ../benchmark/opaque_log.txt
# sudo stop new-opaque-bench
# echo "opaque and sparksql done"



