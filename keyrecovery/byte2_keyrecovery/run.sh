#!/bin/bash

runs=100

program="./keyrecovery_byte2"


date
for (( i=1;i<=$runs;i++ )) 
do
    echo $i
    $program
done
date
