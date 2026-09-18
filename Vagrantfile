# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"
  config.vm.hostname = "seclab"

  # This host directory is shared into the VM as /vagrant/labs (crackme binaries, etc.)
  config.vm.synced_folder ".", "/vagrant/labs"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "security-labs"
    vb.memory = 4096
    vb.cpus = 2
  end

  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    # Enable the i386 architecture to run/debug 32-bit x86 binaries
    dpkg --add-architecture i386
    apt-get update

    # Base build/debug tools (multilib included for 32-bit binaries)
    apt-get install -y \
      build-essential gcc-multilib g++-multilib \
      gdb gdb-multiarch \
      git curl wget vim tmux file \
      ltrace strace \
      binutils nasm \
      netcat-openbsd socat \
      python3 python3-pip python3-dev \
      libssl-dev libffi-dev \
      patchelf elfutils \
      unzip

    # radare2 may be missing on some boxes, so keep going if it fails
    apt-get install -y radare2 || echo "radare2 not available, skipping"

    # 32-bit runtime/debug libraries (run 32-bit crackmes + libc symbols in gdb)
    apt-get install -y \
      libc6:i386 libc6-dbg:i386 libc6-dbg \
      libstdc++6:i386 libncurses6:i386 zlib1g:i386

    # pwntools (includes checksec, cyclic, shellcraft, ...)
    pip3 install --upgrade pip
    pip3 install pwntools ropgadget

    # pwndbg (gdb extension)
    if [ ! -d /opt/pwndbg ]; then
      git clone https://github.com/pwndbg/pwndbg /opt/pwndbg
      cd /opt/pwndbg && ./setup.sh
      # the vagrant user must be able to write to the venv when running gdb
      chown -R vagrant:vagrant /opt/pwndbg
      sudo -u vagrant bash -c 'echo "source /opt/pwndbg/gdbinit.py" > ~/.gdbinit'
    fi

    # Disable ASLR for lab convenience (set the value back to 2 after class)
    echo "kernel.randomize_va_space = 0" > /etc/sysctl.d/99-lab-aslr.conf
    sysctl -p /etc/sysctl.d/99-lab-aslr.conf

    # Write core dumps to the current directory
    echo "kernel.core_pattern = core.%p" > /etc/sysctl.d/99-lab-core.conf
    sysctl -p /etc/sysctl.d/99-lab-core.conf

    echo "==== provisioning done ===="
  SHELL
end
