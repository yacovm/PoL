#!/bin/bash

servers="ec2-54-144-121-61.compute-1.amazonaws.com ec2-54-86-56-104.compute-1.amazonaws.com"
#servers="ec2-54-158-67-205.compute-1.amazonaws.com"

for server in $servers; do
	go build
	ssh -i ~/Downloads/aws.pem ubuntu@$server "pkill bench"
	ssh -i ~/Downloads/aws.pem ubuntu@$server "rm -rf levelDB"
	scp -i ~/Downloads/aws.pem bench ubuntu@$server:
	#scp -i ~/Downloads/aws.pem run.sh ubuntu@$server:
	ssh -i ~/Downloads/aws.pem ubuntu@$server "bash run.sh"
done


