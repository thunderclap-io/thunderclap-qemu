#!/bin/sh -e

TREE=$1
PROJECT=$2

# assume we've already compiled Quartus project
quartus_cpf -c $TREE/output_files/$PROJECT.sof $TREE/output_files/$PROJECT.rbf
