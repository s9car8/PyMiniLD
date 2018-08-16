#!/usr/bin/env python3

import argparse
import elf

from dataclasses import asdict



DEFAULT_LIBS = ['libc.so.6']


parser = argparse.ArgumentParser(
        description='Link a couple of object files to one executable ro shared object file.')
parser.add_argument('input', type=str, nargs='+', help='')
parser.add_argument('--libs', '-l', action='append', help='Needed libraries.')
parser.add_argument('--output', '-o', help='Output file name.')

args = parser.parse_args()
# print(args)


elf.run_linking(
        fins=map(lambda name: open(name, 'rb'), args.input),
        fout=open(args.output, 'wb'),
        libs=DEFAULT_LIBS + (args.libs or []))
