This is helper files for benchmarking opaque and spark SQL

1. start opaque docker : sudo docker run -it -m 64g -name opaque-bench -w /home/opaque/opaque ankurdave/opaque bash
2. copy Benchmark.scala(opaque/src/main/scala/edu/berkeley/cs/rise/opaque/benchmark/Benchmark.scala) and build.sbt(opaque/build.sbt) to corresponding container file location
3. copy dataset into container's location(opaque/data/bdb/)
4. execute it : sudo docker exec -w /home/opaque/opaque opaque-bench build/sbt run edu.berkeley.cs.rise.opaque.benchmark.Benchmark
5. collect logs and analyze