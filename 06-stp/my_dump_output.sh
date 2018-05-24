#!/bin/bash

for i in `seq 1 10`;
do
	echo "NODE b$i dumps:";
	tail -7 b$i-output.txt;
	echo "";
done
