FROM ubuntu:18.04

RUN apt-get update && \
	apt-get install -y wget automake autoconf libtool pkg-config && \
    apt-get install -y curl libssl-dev libgcc1 && \
	apt-get install -y git make gcc python3 python curl wget libgcc1 cmake && \
	# These libraries are needed for bindgen as it uses libclang.so
	apt-get install -y clang libclang-dev && \
	# Needed for Open SSL
	apt-get install -y pkg-config libssl-dev

WORKDIR /tmp
RUN git clone https://github.com/opendnssec/SoftHSMv2.git \
	&& cd SoftHSMv2 \
	git reset --hard 20a53bd083a6134ce2230f80edda5dc8be0366bd
RUN cd sh autogen.sh \
		&& ./configure --disable-gost \
		&& make \
		&& make install

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456
