FROM ubuntu
RUN apt update -y \ && apt install -y tcpdump 
#\&& apt-get install -y wget \&& apt-get install net-tools \&& rm -rf /var/lib/apt/lists/*
RUN apt install gcc -y
RUN apt install redis-server -y
RUN apt install -y libhiredis-dev 
COPY ["add.c","log.c","./"]
RUN gcc add.c log.c -o backend -lhiredis
CMD ./backend

