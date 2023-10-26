#!/bin/bash

runs=100

program="./keyrecovery_byte4"


date
for (( i=1;i<=$runs;i++ )) 
do
    echo $i
    $program
done
date
