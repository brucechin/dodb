#!/bin/bash
wget https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.gz .
tar xzvf boost_1_71_0.tar.gz
rm boost_1_71_0.tar.gz
pushd boost_1_71_0/
./bootstrap.sh --prefix=../boost
./b2 install
popd
rm -rf boost_1_71_0
