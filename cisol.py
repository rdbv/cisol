#!/usr/bin/python3

from CodeGenerator import *
from argparse import *
from os import system

argp = ArgumentParser()
argp.add_argument("-f", help="File", dest="src_name")
argp.add_argument("-o", help="Output C filename", default='out.c', dest="out_name")
argp.add_argument("-b", help="Begin offset", default=0, dest="begin_off")
argp.add_argument("-e", help="End offset", default=0, dest="end_off")
argp.add_argument("-use-flags", help="Select flags to use", default='czao', dest="flags_used")


args = vars(argp.parse_args())

filename = args['src_name']
flagsUsed = [x for x in args['flags_used']]
begin, end = (int(args['begin_off'], 16), int(args['end_off'], 16) )

if filename == None:
    argp.print_help()
    exit(0)

cg = CodeGenerator(filename, begin, end, flagsUsed)

cCode = cg.getAsC()

out = open('out.c', 'wb')
out.write(bytes(cCode, encoding='ascii'))
out.close()

print('==== translated... ====')
print(cCode)

#system("gcc out.c -o out")




