#!/usr/bin/env python3
import os,sys
from os import path
import re

'''

First download a bunch of malware from vx-underground.org.

I recommend something like: wget -r --no-parent --reject "index.html*" https://samples.vx-underground.org/APTs/

You will want to unzip most of those, too with something like: find * -name "*.7z" | while read filename; do 7z e -aos $filename -pinfected -o"`dirname "$filename"`"; done;

Delete any chaff once you've unrard and unzipped: find * -name '*.7z' -delete

Now you've got raw files in a directory structure, but when you do yara matches, you don't know what they are. 

Use this script to help massage your directory tree, and rename the malware parent directory after the PDF from the original report. 

This folder /Users/steve/samples.vx-underground.org/APTs/2022/2022.01.03

Becomes this /Users/steve/samples.vx-underground.org/APTs/2022/2022.01.03 BlackLotusLabs-KONNI

This way, when you run a yara scan, you can see the matching file path and a quick snippet of context about the matched file. Super basic.

'''

def get_all_files(treeroot):
    for dir,subdirs,files in os.walk(treeroot):
        for f in files: 
            if f in __file__: continue
            if f.lower().endswith('.pdf'):
                fullpath = os.path.realpath( os.path.join(dir,f) )
                no_ext = os.path.basename(f).split('.pdf')[0]
                parent = os.path.dirname(fullpath)
                file_count = len(files)
                grandparent = os.path.dirname(parent)
                sanitized_no_ext = re.sub(r"[^a-zA-Z0-9-\s_]", "", no_ext)
                sanitized_newnewpath = grandparent + " " + sanitized_no_ext
                print("New name: " + sanitized_newnewpath)
                print("\n")
                #do renaming; run a test before you uncomment the lines below and actually do the renaming...
                if file_count == 1:
                   os.rename(grandparent,sanitized_newnewpath)
def main():
    top_dir="."
    get_all_files(top_dir)
    
if __name__ == '__main__' : main()