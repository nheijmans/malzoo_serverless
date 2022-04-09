# Define function directory
ARG FUNCTION_DIR="/function"
FROM ubuntu:18.04
# Set default workdir and copy in the files
WORKDIR /app
# Update the repository sources list and install prerequisites
RUN apt-get update && \
apt-get update && \
apt-get install -y build-essential pkg-config wget libtool make gcc automake git python3 python3-dev python3-pip libssl-dev cmake && \
# Install YARA
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
RUN pip3 install yara-python boto3 awslambdaric
# Copy function code
COPY app/* /function/
WORKDIR ${FUNCTION_DIR}
ENV PYTHONIOENCODING="utf8"
ENV BucketName="malzoo-serverless-v1-231446340191-malware"
ENTRYPOINT [ "python3", "-m", "awslambdaric" ]
CMD ["yara_worker.handler"]
