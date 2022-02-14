#!/usr/bin/env python
import binascii
from os import error
import sys
import argparse
import os.path
import re

'''
.d88b 8888 888b. 8888 888b. 888b. .d88b. 
8P    8www 8  .8 8www 8wwwP 8  .8 8P  Y8 
8b    8    8wwK' 8    8   b 8wwK' 8b  d8 
`Y88P 8888 8  Yb 8888 888P' 8  Yb `Y88P' 
                                         
This is Cerebro, a quick and simple script to take a list of strings and spit out mutations in YARA friendly format.

Example input: a text file containing a list of strings such as "VirtualAlloc"
Example output: a list of mutations of those strings such as $a01_VirtualAlloc = "hllochualAhVirt" nocase ascii wide

'''
  
def make_stackpush_strings(thing):
    try: 
        if isinstance(thing,str):
            n = 4
            out = [(thing[i:i+n]) for i in range(0, len(thing), n)]
            out.reverse()
            thing_stackpush=str('h'+'h'.join(map(str,out)))
            return(thing_stackpush)
    except:
        print("Uh oh, something bad happened in stackpush func.")

def make_flipflop_strings(thing):
    try:
        if isinstance(thing,str):
            str_len = len(thing)
            s = thing
            t = ""
            thing_flip = t.join([ s[x:x+2][::-1] for x in range(0, len(s), 2) ])
            return(thing_flip)
    except:       
        print("Uh oh, something bad happened in flipflop func.")

def make_reverse_strings(thing):
    try: 
        if isinstance(thing,str):
            string_length = len(thing)
            reversed_string = thing[string_length::-1]
            return(reversed_string)
    except:
        print("Uh oh, something bad happened in reverse func.")

def make_hex_encoded_strings(thing):
    # Hex encoding courtesy of @greglesnewich
    try:
        if isinstance(thing,str):
            s = thing.encode('utf-8')
            t = ""
            thing_hex = t.join(s.hex())
            return(thing_hex)
    except:       
        print("Uh oh, something bad happened in hex encoding func.")

def make_fallchill_strings(thing):
    # Lifted from https://lifars.com/wp-content/uploads/2021/09/Lazarus.pdf
    try:
        if isinstance(thing,str):
            s = ''
            for i in range (0, len(thing)):
                b = hex(ord(thing[i]))
                b = int(b,16)
                if (b > 0x61) and (b < 0x7a):
                    c = int("0xdb",16) - b
                    s = s + str(bytearray.fromhex(str(hex(c))[2:]).decode())
                else:
                    s = s + thing[i]
            return(s)
    except:       
        print("Is that a real string? Something bad happened in fallchill func.")

# Add additional custom mutation functions ^ do things like reverse strings in diff formats, camel case, custom b64, b62, etc etc. 


def assemble_output(clean_str,mut_type,mutated_str):
    # Use this function to change how you prefer things to be formatted in the output. 
    # If you're feeling spunky maybe do a couple of versions, nocase ascii wide, xor, base64 base64 wide and so forth.
    hextype = "hex"
    if hextype in mut_type and not "_hex_enc_str" in mut_type:
        print("\t$" + clean_str + mut_type + " = {" + mutated_str + "}")
    else: 
        #replace " with \"
        yara_mutated_str1 = re.sub(r'\\',r'\\\\', mutated_str)
        #replace \ with \\
        yara_mutated_str2 = re.sub('"','\\"', yara_mutated_str1)
        print("\t$" + clean_str + mut_type + " = \"" + yara_mutated_str2 + "\" nocase")

def main_active(args = sys.argv[1:]):
    
    parser = argparse.ArgumentParser(prog = "cerebro.py", description="Cerebro is a script for finding mutants. This takes a file of newline separated strings and dump you out mutations of strings in YARA friendly formats. Beware, case sensitive inputs may yield less-than-optimal outputs.")

    #File type input, but you could easily add a string input for oneoffs too.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f','--file', type=argparse.FileType('r'), help='Single file to read.')
   
    #Mutation selection choices.
    parser.add_argument('-m','--mut','--mutation', choices=['flipflop','stackpush','reverse','fallchill','hex'], type=str, required=True)

    args = parser.parse_args(args)

    #Do stuff with arguments.
    if args.file:
            mutation = args.mut
            print("\n")
            if mutation == "flipflop":
                mut_type = "_flipflop"
                count = 0
                for line in args.file:
                    in_string = line.strip()
                    mutated_str = make_flipflop_strings(in_string)
                    clean_str = re.sub('\W+','',line.strip())
                    assemble_output(clean_str,mut_type,mutated_str)
                    count +=1
            elif mutation == "stackpush":
                mut_type = "_stackpush"
                count = 0
                for line in args.file:
                    in_string = line.strip()
                    mutated_str = make_stackpush_strings(in_string)
                    clean_str = re.sub('\W+','',line.strip())
                    assemble_output(clean_str,mut_type,mutated_str)
                    count +=1
            elif mutation == "reverse":
                mut_type = "_reverse"
                count = 0
                for line in args.file:
                    in_string = line.strip()
                    mutated_str = make_reverse_strings(in_string)
                    clean_str = re.sub('\W+','',line.strip())
                    assemble_output(clean_str,mut_type,mutated_str)
                    count +=1
            elif mutation == "fallchill":
                mut_type = "_fallchill"
                count = 0
                for line in args.file:
                    in_string = line.strip()
                    mutated_str = make_fallchill_strings(in_string)
                    clean_str = re.sub('\W+','',line.strip())
                    assemble_output(clean_str,mut_type,mutated_str)
                    count +=1
            elif mutation == "hex":
                mut_type = "_hex_enc_str"
                count = 0
                for line in args.file:
                    in_string = line.strip()
                    mutated_str = make_hex_encoded_strings(in_string)
                    clean_str = re.sub('\W+','',line.strip())
                    assemble_output(clean_str,mut_type,mutated_str)
                    count +=1
            print("\n")
            args.file.close()
    else:
        args.file.close()
        print("Was not arg'd --file, probably why nothing happened.")

#### main main

if __name__ == '__main__':
    main_active()
