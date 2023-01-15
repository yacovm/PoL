#!/bin/bash

servers="ec2-3-239-40-20.compute-1.amazonaws.com ec2-34-201-48-42.compute-1.amazonaws.com ec2-18-233-223-137.compute-1.amazonaws.com"

for server in $servers; do
	go build
	ssh -i ~/Downloads/aws.pem ubuntu@$server "pkill bench"
	scp -i ~/Downloads/aws.pem bench ubuntu@$server:
	#scp -i ~/Downloads/aws.pem run.sh ubuntu@$server:
	ssh -i ~/Downloads/aws.pem ubuntu@$server "bash run.sh"
done


