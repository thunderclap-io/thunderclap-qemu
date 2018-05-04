#!/bin/sh

PATH=$1
PROJECT=$2

# assume we've already compiled Quartus project
quartus_cpf $1/output_files/$2.sof $1/output_files/$2.rbf
