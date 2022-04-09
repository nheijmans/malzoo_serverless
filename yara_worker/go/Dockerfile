# Define function directory
ARG FUNCTION_DIR="/function"
FROM ubuntu:18.04
# Set default workdir and copy in the files
WORKDIR /app
# Update the repository sources list and install prerequisites
RUN apt-get update && \
apt-get update && \
apt-get install -y build-essential pkg-config wget libtool make gcc automake git && \
# Install go
wget https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz && \
tar -xvf go1.15.2.linux-amd64.tar.gz && \
mv go /usr/local && \
export PATH=$PATH:/usr/local/go/bin && \
#Install YARA
wget https://github.com/VirusTotal/yara/archive/v4.1.0.tar.gz && \
tar -zxf v4.1.0.tar.gz && \
cd yara-4.1.0 && \
./bootstrap.sh && \
./configure && \
make && \
make install && \
echo "/usr/local/lib" >> /etc/ld.so.conf && \
ldconfig
ARG FUNCTION_DIR
# Create function directory
RUN mkdir -p ${FUNCTION_DIR}
# Copy function code
COPY app/* ${FUNCTION_DIR}
RUN cd ${FUNCTION_DIR} && \
# Start with building the yara binary
export PATH=$PATH:/usr/local/go/bin && \
go mod init github.com/hillu/go-yara && \
go get ./... && \
go get -u github.com/aws/aws-lambda-go/events && \
go get -u github.com/aws/aws-lambda-go/lambda && \
go get -u github.com/aws/aws-sdk-go/aws && \
go get -u github.com/aws/aws-sdk-go/aws/session && \
go get -u github.com/aws/aws-sdk-go/service/s3 && \
go get -u github.com/aws/aws-sdk-go/service/s3/s3manager
RUN export PATH=$PATH:/usr/local/go/bin && \ 
cd ${FUNCTION_DIR} && \
GO111MODULE=auto go build -o yaraworker yaraworker.go flags.go awstooling.go && echo "done!"
ENTRYPOINT [ "/function/yaraworker"]