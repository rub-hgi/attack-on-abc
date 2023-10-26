# README for Source-Code of the ABC attack implementation

Compile with:

    make

Usage: 

#   Computing the DDT_r for r \in \{2,4,6\}
    ./armamatrix [-read <file>] [-read2 <file>] [-write <file>] [-m]

#   Performing the MITM-attack on Byte2
    ./mitm 

#   Differential attack on Byte2:
    cd keyrecovery/byte2_keyrecovery && ./keyrecovery_byte2 [-v] [<LEN>]

#   Differential attack on Byte4:
    cd keyrecovery/byte4_keyrecovery && ./keyrecovery_byte4 [-v] [<LEN>]

#   Implementation of Byte2:
    cd keyrecovery/byte2_keyrecovery && ./byte2 <p> <k> <r> [-inv]

#   Implementation of Byte4:
    cd keyrecovery/byte4_keyrecovery && ./byte4 <p> <k> <r> [-inv]

#   Computing the statistics for all-in-one differential Byte2:
    cd keyrecovery/byte2_keyrecovery && ./stats_differential_attacks_byte2 [-all] [<min> <max> <step>]

#   Computing the statistics for all-in-one differential Byte4:
    cd keyrecovery/byte4_keyrecovery && ./stats_differential_attacks_byte4 [-all] [<min> <max> <step>]

#   Analysing the keyschedule:
    cd keyrecovery/keyschedule && ./masterkeyrecovery.cpp
    (Just a sketch, does not run in realistic time on a standard computer)
