# Pulling the base image
FROM ubuntu:latest

# Naming the image author
MAINTAINER elQanabel-Seniors

# Adding the code to the docker image
ADD . /code
WORKDIR /code

# updating the platform
RUN apt-get update && apt-get -y install sudo
# Installing the g++ complier
RUN echo "y" | sudo apt-get install g++
# Compiling the program source code
RUN g++ -o virus.exe MemAllocator.cpp
RUN g++ -o virus2.exe virus2_hastobeterminated.cpp
RUN g++ -o scanner.exe scanner.cpp

# Running the virus program
#CMD ./program.exe
