#!/usr/bin/env python
import binascii
from os import error
import sys, string, struct
from datetime import date
import argparse
import os.path
import itertools as it
import encodings
import fileinput
import re
import base64

'''
.d88b 8888 888b. 8888 888b. 888b. .d88b. 
8P    8www 8  .8 8www 8wwwP 8  .8 8P  Y8 
8b    8    8wwK' 8    8   b 8wwK' 8b  d8 
`Y88P 8888 8  Yb 8888 888P' 8  Yb `Y88P' 
                                         
This is Cerebro "String", a quick and simple script to take a single input string and spit out mutations in YARA friendly format.

If this doesn't work, because of your Python install and paths... make sure you've got everything in Python2 or Python3 as needed.

Example input: a string such as "VirtualAlloc"
Example output: a list of mutations of those strings such as $a01_VirtualAlloc = "hllochualAhVirt" nocase ascii wide

Usage:

python3 cerebro-string-basic.py -s kernel32.dll -m frenchstack
python3 cerebro-string-basic.py --str GetCurrentProcess --mut hex 
python3 cerebro-string-basic.py -s IsDebuggerPresent --mut a
ll

'''

# frenchstack stuff below courtesy of @notareverser https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca

def strByByte(_strval):
    strval = bytearray(_strval.encode())
    for s in strval: yield s

def strByDword(_strval):
    strval = bytearray(_strval.encode())
    numDwords = int(len(strval) / 4)
    remainder = len(strval) - (numDwords*4)

    for x in range(numDwords):
        yield struct.unpack_from("<L", strval, 4*x)[0]
    if remainder != 0:
        remainderVals = strval[4*numDwords:]
        remainderVals.extend(bytearray([0]*(4-remainder)))
        yield struct.unpack("<L", remainderVals)[0]

        
def hexlify(v): return '{:x}'.format(v)
def strToHex(strval): return ''.join(list(map(lambda k: '{:02x}'.format(ord(k)), strval)))
def bufToHex(bval): return ''.join(list(map(lambda k: '{:02x}'.format(k), bval)))


    
def doPrototype(proto, _strval):
    strval = bytearray(_strval.encode())
    v = []
    for s in strval: v.append(proto.format(s))
    return ' '.join(v)

def generateSmallStack(strval):
    return '   $smallStack = {' + doPrototype('c645??{:02x}', strval) +'}'

def generateLargeStack(strval):
    return '   $largeStack = {' + doPrototype('c7(45|85)[1-4]{:02x}000000', strval) + '}'

def generateRegister(strval):
    return '   $register = {'+ doPrototype('b?{:02x}000000 6689????', strval) + '}'

def generateDword(_strval):
    strval = bytearray(_strval.encode())
    numDwords = int(len(strval)/4)
    remainder = len(strval) - (numDwords*4)

    values = []
    for x in range(numDwords):
        nextd = struct.unpack_from("<L", strval, 4*x)[0]
        values.append('c7(45|85)[1-4]{:08x}'.format(nextd))
    if remainder > 0:
        if remainder == 3:
            firstv, secondv = struct.unpack("<HB", strval[-remainder:])
            print(firstv, secondv, "oops - something bad happened in generateDword")
            #print(firstv, secondv,file=sys.stderr)
            values.append('[0-1]c7(45|85)[1-4]{:04x}'.format(firstv))
            values.append('[0-1]c6(45|85)[1-4]{:02x}'.format(secondv))
        elif remainder == 2:
            firstv = struct.unpack("<H", strval[-remainder:])[0]
            values.append('[0-1]c7(45|85)[1-4]{:04x}'.format(firstv))
        elif remainder == 1:
            values.append('[0-1]c6(45|85)[1-4]{:02x}'.format(strval[-1]))
    
    return '   $dword = {'+(' '.join(values))+ '}'

def generatePushPop(strval):
    return ('   $pushpop = {'+
            doPrototype('6a{:02x}5? ', strval[0]) +
            doPrototype('6a{:02x} 6689????5?', strval[1:-1]) + '}')
            
def generateCallOverString(strval):
    return ('   $callOverString = {e8'+
            bufToHex(struct.pack("<L", len(strval))) +
            strToHex(strval) + '5? }')

def fixName(strval):
    result = []
    valid = string.ascii_letters + string.digits + '_'
    for s in strval:
        result.append('_' if s not in valid else s)
    return ''.join(result)

def generate(strval):
    nl = '\n'
    clauses = []
    clauses.append("rule stackstring_{}".format(fixName(strval)))
    clauses.append("{")
    clauses.append("  strings:")
    
    clauses.append(generateSmallStack(strval)+nl)
    clauses.append(generateLargeStack(strval)+nl)
    clauses.append(generateRegister(strval)+nl)
    clauses.append(generateDword(strval)+nl)
    clauses.append(generatePushPop(strval)+nl)
    clauses.append(generateCallOverString(strval)+nl)
    
    clauses.append("  condition:")
    clauses.append("    any of them")
    clauses.append("}")
    
    print(nl.join(clauses)+nl+nl)

# frenchstack stuff above courtesy of @notareverser https://gist.github.com/notareverser/4f6b9c644d4fe517889b3fbb0b4271ca

  
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


def make_stackpush_nullterm(thing):
    try: 
        if isinstance(thing,str):
            n = 4
            out = [(thing[i:i+n]) for i in range(0, len(thing), n)]
            out.reverse()
            thing_stackpush=str('h'+'h'.join(map(str,out)))
            index = thing_stackpush.find('h',1)
            final = thing_stackpush[:index] + "\\" + "x00" + thing_stackpush[index:]
            return(final)
    except:
        print("Uh oh, something bad happened in stackpush_nullterm func.")

def make_stackpush_doublenullterm(thing):
    try: 
        if isinstance(thing,str):
            n = 4
            out = [(thing[i:i+n]) for i in range(0, len(thing), n)]
            out.reverse()
            thing_stackpush=str('h'+'h'.join(map(str,out)))
            index = thing_stackpush.find('h',1)
            final = thing_stackpush[:index] + "\\" + "x00" + "\\" + "x00" + thing_stackpush[index:]
            return(final)
    except:
        print("Uh oh, something bad happened in stackpush_nullterm func.")

# Add additional custom mutation functions ^ do things like reverse strings in diff formats, camel case, custom b64, b62, etc etc. 


def assemble_output(clean_str,mut_type,mutated_str):
    # Use this function to change how you prefer things to be formatted in the output. 
    # If you're feeling spunky maybe do a couple of versions, nocase ascii wide, xor, base64 base64 wide and so forth.
    if "\\x00" in mutated_str:
        print("\t$" + clean_str + mut_type + " = \"" + mutated_str + "\"")
    elif "_hex_" in mut_type and not "_hex_enc_str" in mut_type:
        print("\t$" + clean_str + mut_type + " = {" + mutated_str + "}")
    else: 
        #replace " with \"
        yara_mutated_str1 = re.sub(r'\\',r'\\\\', mutated_str)
        #replace \ with \\
        yara_mutated_str2 = re.sub('"','\\"', yara_mutated_str1)
        print("\t$" + clean_str + mut_type + " = \"" + yara_mutated_str2 + "\" nocase")

def main_active(args = sys.argv[1:]):
    
    parser = argparse.ArgumentParser(prog = "cerebro-string-basic.py", description="Cerebro is a script for finding mutants. This takes a single string and dumps you out mutations of strings in YARA friendly formats. Beware, case sensitive inputs may yield less-than-optimal outputs.")

    # File type input, but you could easily add a string input for oneoffs too.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s','--str', type=str, help='Single string to mutate.')
   
    # Mutation selection choices.
    parser.add_argument('-m','--mut','--mutation', choices=['flipflop','reverse','stackpush','stackpushnull','stackpushdoublenull','hex','fallchill','all','frenchstack'], type=str, required=True)

    args = parser.parse_args(args)

    # Do stuff with arguments.
    clean_str = re.sub('\W+','',args.str.strip())
    in_string = args.str
    mutation = args.mut
    if args.str:
            clean_str = re.sub('\W+','',args.str.strip())
            in_string = args.str
            mutation = args.mut
            if args.mut:
                print("\n")
                if mutation == "flipflop":
                    mut_type = "_flipflop"
                    mutated_str = make_flipflop_strings(in_string)
                    assemble_output(clean_str,mut_type,mutated_str)
                elif mutation == "stackpush":
                    mut_type = "_stackpush"
                    mutated_str = make_stackpush_strings(in_string)
                    assemble_output(clean_str,mut_type,mutated_str) 
                elif mutation == "stackpushnull":
                    mut_type = "_stackpushnull"
                    mutated_str = make_stackpush_nullterm(in_string)
                    assemble_output(clean_str,mut_type,mutated_str) 
                elif mutation == "stackpushdoublenull":
                    mut_type = "_stackpushdoublenull"
                    mutated_str = make_stackpush_doublenullterm(in_string)
                    assemble_output(clean_str,mut_type,mutated_str)       
                elif mutation == "reverse":
                    mut_type = "_reverse"
                    mutated_str = make_reverse_strings(in_string)
                    assemble_output(clean_str,mut_type,mutated_str)   
                elif mutation == "fallchill":
                    mut_type = "_fallchill"
                    mutated_str = make_fallchill_strings(in_string)
                    assemble_output(clean_str,mut_type,mutated_str)
                elif mutation == "hex":
                    mut_type = "_hex_enc_str"
                    mutated_str = make_hex_encoded_strings(in_string)
                    assemble_output(clean_str,mut_type,mutated_str)
                elif mutation == "frenchstack":
                    generate(in_string)
                elif mutation == "all": #everything but frenchstack
                    funcs = [
                            make_flipflop_strings(in_string),
                            make_reverse_strings(in_string),
                            make_hex_encoded_strings(in_string),
                            make_fallchill_strings(in_string),
                            make_stackpush_strings(in_string),
                            make_stackpush_nullterm(in_string),
                            make_stackpush_doublenullterm(in_string)
                    ]
                    mut_types = ["_flipflop","_reverse","_hex_enc_str","_fallchill","_stackpush","_stackpushnull","_stackpushdoublenull"]
                    i = 0
                    for f in funcs:
                        mut_type = mut_types[i]
                        i+=1
                        mutated_str = f
                        assemble_output(clean_str,mut_type,mutated_str)
                else:
                    print("\nSomething bad happend with mutation selection.\n")
                print("\n")
            else:
                print("\nError in mutations selection.\n")
#### main main

if __name__ == '__main__':
    main_active()
