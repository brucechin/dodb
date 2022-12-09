sudo apt update
sudo apt -y install wget cmake make
sudo apt -y install libssl-dev libcurl4-openssl-dev libprotobuf-dev bison flex
sudo apt -y install build-essential python python-pip
sudo apt-get -y install \
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
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
pip install -r requirements.txt

# wget https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.gz
# tar -zxvf boost_1_71_0.tar.gz
# cd boost_1_71_0
# sudo ./bootstrap.sh --prefix=/usr
# sudo ./b2 stage -j 8 threading=multi link=shared
# sudo ./b2 install threading=multi link=shared


# it seems that after rebooting the computer, we have to reinstall the SGX driver to make it work...
wget https://download.01.org/intel-sgx/linux-1.9/sgx_linux_x64_driver_3abcf82.bin
chmod +x sgx_linux_x64_driver_3abcf82.bin
sudo ./sgx_linux_x64_driver_3abcf82.bin

wget https://download.01.org/intel-sgx/linux-1.9/sgx_linux_ubuntu16.04.1_x64_psw_1.9.100.39124.bin
chmod +x sgx_linux_ubuntu16.04.1_x64_psw_1.9.100.39124.bin
sudo ./sgx_linux_ubuntu16.04.1_x64_psw_1.9.100.39124.bin

wget https://download.01.org/intel-sgx/linux-1.9/sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin
chmod +x sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin
sudo ./sgx_linux_ubuntu16.04.1_x64_sdk_1.9.100.39124.bin
source /home/ubuntu/sgxsdk/environment
