FROM ubuntu:16.04
RUN	\
	dpkg --add-architecture armhf && \
	mv /etc/apt/sources.list /tmp/sources.list && \
	sed -i 's/deb/deb [arch=amd64]/g' /tmp/sources.list && \
	grep -v "armhf" /tmp/sources.list > /etc/apt/sources.list && \
	echo "deb [arch=armhf] http://ports.ubuntu.com/ xenial main universe multiverse" >> /etc/apt/sources.list && \
	echo "deb [arch=armhf] http://ports.ubuntu.com/ xenial-updates main universe multiverse" >> /etc/apt/sources.list && \
	cat /etc/apt/sources.list && \
	apt-get update && \
	apt-get -y install binutils-arm-linux-gnueabihf gcc-5-arm-linux-gnueabihf build-essential && \
	apt-get -y install gettext:armhf libglib2.0-dev:armhf libpcre3-dev:armhf libpixman-1-dev:armhf
