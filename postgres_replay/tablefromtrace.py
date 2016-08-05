# SPDX-License-Identifier: BSD-2-Clause
# 
# Copyright (c) 2015-2018 Colin Rothwell
# 
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
# 
# We acknowledge the support of EPSRC.
# 
# We acknowledge the support of Arm Ltd.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# Have a CSV file with loads of cruft.
# Outputs "create_table.sql" to create the table
# It assumes you are generating a table where a previous version existed, so
# includes a number of "DROP" commands. Delete these if you don't need them.
# To import into PGAdmin, the file format generated is "text", and you need to
# set it to not import the "pk" field from file.
# Outputs "cleaned_data.txt" for use with the COPY FROM command
# The input file is hardcoded in, sorry. Grep for ".csv"

# A bunch of conversion with optionally return the value '', because it is valid
# for SQL cells to be empty, and many packets don't have certain fields.

# XXX: All IOWr have data "1 dword"

# We want to:
# * For decimal integer columns:
#   - Assert that values are integers.
#   - Work out correct size of column.
# * Create enums for all var-char columns that have fewer than 32 possible
#   variations.
# * Convert ids into integers. (Hex 8 bits bus num, 5 bits deb num, 3 bits fn)

from __future__ import print_function

import csv
import sys

from enum import Enum

ENUM_SIZE_LIMIT = 32
NULL_STRING = '\N'
NAMESPACE = 'qemu_'

DataType = Enum('DataType', 'bin_int dec_int hex_int varchar device_id')
int_data_types = frozenset({DataType.bin_int, DataType.dec_int,
                            DataType.hex_int})

def convert_device_id(raw):
    if raw == '':
        return NULL_STRING
    bus, dev, func = map(lambda num: int(num, 16), raw.split(':'))
    assert 0 <= bus < 2 ** 8
    assert 0 <= dev < 2 ** 5
    assert 0 <= func < 2 ** 3
    return bus << 8 | dev << 3 | func

def int_blank_to_null(string, base):
    if string == '':
        return NULL_STRING
    else:
        return int(string, base)

converters = {
    DataType.bin_int: lambda raw: int_blank_to_null(raw, 2),
    DataType.dec_int: lambda raw: int_blank_to_null(raw, 10),
    DataType.hex_int: lambda raw: int_blank_to_null(raw, 16),
    DataType.varchar: lambda raw: raw,
    DataType.device_id: convert_device_id
}

def column_record(name=None, data_type=DataType.varchar):
    record = {
        'name': name,
        'type': data_type,
        'seen_values': None,
        'longest_length': None,
        'min': None,
        'max': None
    }
    assert data_type in DataType, data_type
    if data_type == DataType.varchar:
        record['seen_values'] = set()
        record['longest_length'] = 0
    elif data_type in int_data_types:
        record['min'] = float('inf')
        record['max'] = float('-inf')
    return record

special_columns = [
    column_record('packet', DataType.dec_int),
    #column_record(
        #'tlp_type',
        #column_dest('fmt', DataType.bin_int, tlp_type_to_fmt),
        #column_dest('type', DataType.bin_int, tlp_type_to_type)
    #),
    column_record('psn', DataType.dec_int),
    column_record('length', DataType.dec_int),
    column_record('requester_id', DataType.device_id),
    column_record('tag', DataType.dec_int),
    column_record('completer_id', DataType.device_id),
    column_record('address', DataType.hex_int),
    column_record('device_id', DataType.device_id),
    column_record('register', DataType.hex_int),
    column_record('first_be', DataType.bin_int),
    column_record('last_be', DataType.bin_int),
    column_record('byte_cnt', DataType.dec_int),
    column_record('bcm', DataType.dec_int),
    column_record('lwr_addr', DataType.hex_int),
    column_record('lcrc', DataType.hex_int),
    column_record('data', DataType.hex_int)
]

ignored_columns = frozenset({
    'ord_set_type',
    'dllp_type',
    'acknak_seq_num',
    'vc_id',
    'hdrfc',
    'datafc',
    'tc',
    'th',
    'td',
    'ep',
    'attributes',
    'at',
    'ts_link',
    'ts_lane',
    'n_fts',
    'training_control',
    'ecrc',
    'crc_16'
})

def column_record_for_name(name):
    for record in special_columns:
        if record['name'] == name:
            return record
    return None

def sqlify_column_name(name):
    if name == '1st BE':
        return 'first_be'
    else:
        to_return = []
        for char in name.replace('ID', '_id'):
            if char.isalnum():
                to_return.append(char.lower())
            elif to_return[-1] != '_':
                to_return.append('_')
        return ''.join(to_return)

def main():
    with open('pcie-qemu-2016080401.csv') as trace_file, \
            open('cleaned_data.txt', 'w') as data_file:
        trace_reader = csv.reader(trace_file)

        column_names = map(sqlify_column_name, next(trace_reader))
        name_to_column_num = {name: i for (i, name) in enumerate(column_names)}
        column_records = []
        for i, name in enumerate(column_names):
            record = column_record_for_name(name)
            if record is None and name not in ignored_columns:
                record = column_record(name)
            column_records.append(record)

        skip_this_row = False
        skip_next_row = False
        for row_num, raw_row in enumerate(trace_reader):
            clean_row = []
            for column_num, raw_data in enumerate(raw_row):
                record = column_records[column_num]
                if record is None:
                    continue
                data_type = record['type']
                try:
                    clean_data = converters[data_type](raw_data)
                except ValueError as ex:
                    print(('ValueError when converting value "{}" for field '
                           '"{}" with type "{}"').format(
                              raw_data, record['name'], record['type']
                          ))
                    raise
                #if record['name'] == 'register' and clean_data in (152, 156):
                    #skip_this_row = True
                    #skip_next_row = True
                    #break

                if clean_data == '':
                    clean_row.append(NULL_STRING)
                else:
                    clean_row.append(str(clean_data))
                if data_type in int_data_types and clean_data != NULL_STRING:
                    record['min'] = min(record['min'], clean_data)
                    record['max'] = max(record['max'], clean_data)
                elif data_type is DataType.varchar:
                    if record['seen_values'] is not None:
                        record['seen_values'].add(clean_data)
                        if len(record['seen_values']) > ENUM_SIZE_LIMIT:
                            record['seen_values'] = None
                    longest = max(record['longest_length'], len(clean_data))
                    record['longest_length'] = longest

            if skip_this_row:
                skip_this_row = False
                continue

            if clean_row[name_to_column_num['tlp_type']] != NULL_STRING:
                #if skip_next_row:
                    #skip_next_row = False
                    #continue
                #else:
                data_file.write('\t'.join(clean_row))
                data_file.write('\n')

            if (row_num + 1) % 10000 == 0:
                sys.stdout.write('.')
                sys.stdout.flush()
    print('Done cleaning data!')
    with open('create_table.sql', 'w') as query_file:
        # Create enum types
        query_file.write('DROP TABLE {}trace;\n'.format(NAMESPACE))
        for record in column_records:
            if record is None:
                continue
            seen_values = record['seen_values']
            if isinstance(seen_values, set):
                seen_values.discard('')
                type_name = '{}{}_enum'.format(NAMESPACE, record['name'])
                query_file.write('DROP TYPE ')
                query_file.write(type_name)
                query_file.write(';\n')
                query_file.write('CREATE TYPE ')
                query_file.write(type_name)
                query_file.write(' AS ENUM (')
                query_file.write(', '.join([
                    "'{}'".format(enum_val) for enum_val in sorted(seen_values)
                ]))
                query_file.write(');\n')
        query_file.write('CREATE TABLE {}trace (\n'.format(NAMESPACE))
        query_file.write('\tpk SERIAL PRIMARY KEY')
        for record in column_records:
            if record is None:
                continue
            assert not record['name'] == 'pk'
            query_file.write(',\n')
            query_file.write('\t')
            query_file.write(record['name'])
            query_file.write(' ')
            if isinstance(record['seen_values'], set):
                query_file.write(NAMESPACE)
                query_file.write(record['name'])
                query_file.write('_enum')
            elif record['type'] in int_data_types:
                l, h = record['min'], record['max']
                if -2 ** 31 <= l and h < 2 ** 31:
                    query_file.write('integer')
                else:
                    query_file.write('bigint')
            elif record['type'] is DataType.varchar:
                query_file.write('varchar(')
                query_file.write(str(record['longest_length']))
                query_file.write(')')
            elif record['type'] is DataType.device_id:
                query_file.write('integer')
        query_file.write('\n);')

if __name__ == '__main__':
    main()
