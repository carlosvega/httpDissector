#!/usr/bin/python
# Author: Carlos Vega
# Version: 0.5
from __future__ import division
import argparse, sys, fileinput, os
from collections import OrderedDict


args = None
f_output = None
version = "0.5"
file_size = 0
toolbar_width = 100
stdin = False
stdout = False

def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Creates an index using the provided column as key, in which each entry specifies the byte position in the file.\nSay we name the chosen column you choose as <key>, by default an entry is created after passing <interval> different <keys>. So between an entry and another there are <interval> different <keys>. For example: If we want to index a file in which the column are IPs, by default is indexed in a way that between an IP index entry and the next there are <interval> different IPs in the original file.\nUsing the option -L we can change this behaviour. With the option -L the indexer creates an entry for every 10 lines.\nWith the option -T, we are assuming that the chosen column is a timestamp (with ms) so the interval is a time in minutes and the indexer creates an entry for each <interval>*60 seconds.')
    
    parser.add_argument('-c', '--column', dest='column', type=int, required=False, default=0, help='Column to be indexed by, column of the <key>. Numbering starting in 0. Zeroth column as default.')
    parser.add_argument('-F', '--no-first-line', dest='no_first_line', action='store_true', default=False, help='Use it if you want to exclude de first line.')
    parser.add_argument('-i', '--input', dest='input', required=False, default='-', help='Input file. Default: stdin.')
    parser.add_argument('-I', '--interval', dest='interval', type=int, required=False, default=None, help='With no -L and -T option the interval is how many different <keys> we want between an entry and the next. With the -L option it would be the line interval whereby each entry is created. In case of using -T option it would mean minutes.')
    parser.add_argument('-L', '--line', dest='line', action='store_true', default=False, help='Use it if the interval is a number of lines. An entry will be created for each interval of lines. Not compatible with option -T.')
    parser.add_argument('-s', '--separator', dest='separator', default=" ", help='Defines the input field separator. Space character as default.')
    parser.add_argument('-S', '--sorted', dest='sorted', action='store_true', default=False, help='Use it if the provided file is sorted. Unsorted input supported just for -T index mode.')
    parser.add_argument('-o', '--output', dest='output', required=False, help='Index output filename. Default: stdout.', default='stdout')
    parser.add_argument('--no-progress-bar', dest='no_progress_bar', action='store_true', default=False, help='Disable progress bar.')
    parser.add_argument('-T', '--time', dest='time', action='store_true', default=False, help='Use it if the chosen column is a timestamp, thus the interval would mean minutes.')
    parser.add_argument('-V', '--version', dest='version', action='store_true', default=False, help='Returns the version of the app.')
    parser.add_argument('--httpdissector', dest='httpDissector', action='store_true', default=False, help='Default parameters for httpDissector input.')
    parser.add_argument('--flowprocess', dest='flowProcess', action='store_true', default=False, help='Default parameters for flowProcess input.')

    args = parser.parse_args()

    if args.time and args.line:
        sys.stderr.write("Invalid parameter. Must choose between -T or -L options, or neither.\n")
        sys.exit(0)

    return args


def progress_bar(progress, byte_counter):
    global args, stdin, stdout, file_size
    progress_bar.calls += 1
    if args.no_progress_bar or stdin or stdout or ((progress_bar.last_byte + progress_bar.file_size) > byte_counter):
        return

    progress_bar.last_byte = byte_counter
    if (int(progress * 100) - progress_bar.counter) >= 1:
        progress_bar.counter += 1
        sys.stderr.write("\b" * (toolbar_width+7)) # return to start of line, after '['
        sys.stderr.write("[%s%s] %3.d%%" % ("-" * progress_bar.counter, " " * (toolbar_width-progress_bar.counter), int(progress*100)))
        sys.stderr.flush()
progress_bar.counter = 0
progress_bar.calls = 0
progress_bar.file_size = (file_size//100)
progress_bar.last_byte = 0

def add_tuple_to_dicc(dicc, k, pair):
    if k not in dicc:
        dicc[k] = []

    dicc[k].append(pair)    

def find_nth(s, substr, n):
    index = -1
    while n:
        index = s.find(substr, index + 1)
        if index == -1:
            return -1
        n-=1

    return index

def header_progress_bar():
    if not (args.no_progress_bar or stdin or stdout):
        sys.stderr.write("[%s] 000%%" % (" " * toolbar_width))
        sys.stderr.flush()
        sys.stderr.write("\b" * (toolbar_width+7)) # return to start of line, after '['

def create_index_with_unsorted_input():

    header_progress_bar()

    global args
    args.interval = args.interval*60
    last_timestamp = 0
    line_counter = 0
    start_byte = 0
    end_byte = 0
    dicc = {}
    for line in fileinput.input(args.input):
        if args.no_first_line and line_counter == 0:
            line_counter += 1
            continue

        if line_counter % 10 != 0:
            line_counter += 1
            end_byte += len(line)
            continue
        
        index = find_nth(line, args.separator, args.column)
        if index == -1:
            sys.stderr.write("\nInvalid column number for the provided separator. Maybe the separator is wrong.\n")
            sys.exit(1)

        indexBy = (int(line[index+1:index+11])//args.interval)*args.interval
        if line_counter == 0:
            last_timestamp = indexBy
        elif indexBy != last_timestamp:
            add_tuple_to_dicc(dicc, last_timestamp, (start_byte, end_byte))
            start_byte = end_byte
            last_timestamp = indexBy

        end_byte += len(line)

        line_counter += 1
        progress_bar(end_byte/file_size, end_byte)

    progress_bar(file_size/file_size, end_byte)
    sys.stderr.write("\n")
    dicc = OrderedDict(sorted(dicc.items(), key=lambda t:t[0]))
    for k in dicc:
        f_output.write('%d %s\n' % (k, dicc[k]))

def parse_with_timestamps():

    header_progress_bar()

    global args
    args.interval = args.interval*60
    last_timestamp = 0
    byte_counter = 0
    line_counter = 0
    for line in fileinput.input(args.input):
        
        if args.no_first_line and line_counter == 0:
            line_counter += 1
            continue

        if line_counter % 10 != 0:
            byte_counter += len(line)
            line_counter += 1
            continue
        else:
            indexBy = float(filter(None, line.split(args.separator))[args.column])
            if indexBy > last_timestamp + args.interval:
                f_output.write('%d %d\n' % (indexBy, byte_counter))
                last_timestamp = indexBy
            byte_counter += len(line)
            line_counter += 1

        progress_bar(byte_counter/file_size, byte_counter)

    progress_bar(file_size/file_size, byte_counter)
    sys.stderr.write("\n")

#creates  entry every <interval>  lines
def index_lines():

    header_progress_bar()

    global args
    byte_counter = 0
    line_counter = args.interval+1

    for line in fileinput.input(args.input):
        if args.no_first_line and line_counter == 0:
            line_counter += 1
            continue

        indexBy = line.split(args.separator)[args.column]
        if line_counter > args.interval:
            f_output.write('%s %d\n' % (indexBy, byte_counter))
            line_counter = 0
        line_counter+=1
        byte_counter+=len(line)

        progress_bar(byte_counter/file_size, byte_counter)

    progress_bar(file_size/file_size, byte_counter)
    sys.stderr.write("\n")

#creates entry each <interval> different lines
def index_different_lines():

    header_progress_bar()

    global args
    byte_counter = 0
    counter = args.interval
    last_indexBy = ""
    line_counter = 0
    for line in fileinput.input(args.input):
        if args.no_first_line and line_counter == 0:
            line_counter += 1
            continue

        indexBy = line.split(args.separator)[args.column]
        if last_indexBy != indexBy:
            if counter == args.interval:
                f_output.write('%s %d\n' % (indexBy, byte_counter))
                counter = 0
                last_indexBy = indexBy
            else:
                counter += 1
                last_indexBy = indexBy
        byte_counter+=len(line)

        progress_bar(byte_counter/file_size, byte_counter, byte_counter)

    progress_bar(file_size/file_size, byte_counter)
    sys.stderr.write("\n")

parse_args()

if args.version:
    sys.stderr.write("Indexer.py " + version + "\n")
    sys.exit(1)

if args.input == '-':
    stdin = True
else:
    file_size = os.path.getsize(args.input)

if args.httpDissector:
    args.time = True
    args.column = 4
    args.separator = "|"
    if args.interval == None:
        args.interval = 5

if args.flowProcess:
    args.time = True
    args.separator = " "
    args.column = 10
    if args.interval == None:
        args.interval = 5

if args.column == 0:
    sys.stderr.write("-c option is mandatory\n")
    sys.exit(1)    

if args.interval == 0:
    sys.stderr.write("-I option is mandatory\n")
    sys.exit(1)    


if not args.time and not args.sorted:
    sys.stderr.write("Unsorted input supported just in -T mode.\n")
    sys.exit(1)    

if args.output == "stdout":
    f_output = sys.stdout
    stdout = True
else:
    f_output = open(args.output, 'w')

try:
    if args.time and args.sorted:
        parse_with_timestamps()
    elif args.time and not args.sorted:
        create_index_with_unsorted_input()
    elif args.line and args.sorted:
        index_lines()
    elif args.sorted:
        index_different_lines()    
        
except IndexError:
    sys.stderr.write("Invalid column number for the provided separator. Maybe the separator is wrong.\n")
except KeyboardInterrupt:
    sys.stderr.write("Aborted by the user.\n")
except IOError, ioex:
    sys.stderr.write("There was a problem reading the file: " + os.strerror(ioex.errno) + ".\n")