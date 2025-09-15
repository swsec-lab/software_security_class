#!/bin/bash

# 시스템 업데이트 및 필수 패키지 설치
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-dev git \
  libssl-dev libffi-dev build-essential \
  gcc g++ gcc-multilib g++-multilib gdb

# pwntools 설치
pip3 install --upgrade pwntools

# pwndbg 설치
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
git checkout 2024.08.29
./setup.sh

# gdb 설정
echo "set disassembly-flavor intel" >> ~/.gdbinit


