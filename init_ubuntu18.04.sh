sudo apt update
sudo apt -y install wget cmake make
sudo apt -y install libssl-dev libcurl4-openssl-dev libprotobuf-dev  bison flex
sudo apt -y install build-essential python python-pip
sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker.io
pip install -r requirements.txt

# wget https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.gz
# tar -zxvf boost_1_71_0.tar.gz
# cd boost_1_71_0
# sudo ./bootstrap.sh --prefix=/usr 
# sudo ./b2 stage -j 8 threading=multi link=shared
# sudo ./b2 install threading=multi link=shared

# it seems that after rebooting the computer, we have to reinstall the SGX driver to make it work...
wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_95eaa6f.bin
chmod +x sgx_linux_x64_driver_2.6.0_95eaa6f.bin
sudo ./sgx_linux_x64_driver_2.6.0_95eaa6f.bin

# echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
# wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
# sudo apt update
# sudo apt install -y libsgx-launch libsgx-epid libsgx-quote-ex libsgx-urts

# because the previous way will install the newest PSW packages which is 2.11 version, we download a specific version and install it ourselves.
# the PSW package contains libsgx_urts.so which will be used for hardware mode dynamic linking. libsgx_urts.so from SGXSDK package can not be used in hardwre mode.
wget https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/libsgx-enclave-common_2.3.101.46683-1_amd64.deb
sudo dpkg -i libsgx-enclave-common_2.3.101.46683-1_amd64.deb
sudo apt update

wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin
chmod +x sgx_linux_x64_sdk_2.9.101.2.bin
sudo ./sgx_linux_x64_sdk_2.9.101.2.bin
# source /home/ubuntu/sgxsdk/environment

