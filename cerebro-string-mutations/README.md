# Cerebro

Scripts and lists to help you brute force YARA friendly string mutations.

- Reference Blog: https://stairwell.com/news/hunting-with-weak-signals/


There are two scripts here, one to help you process files with string lists, and one to help you do one off strings in multiple mutation forms.

- cerebro-file-basic.py
- cerebro-string-basic.py


## Mutations

- flipflop - Flipping every two bytes, encoding used in many malware families including Nobelium's FLIPFLOP
- stackpush - Meterpreter-style x86 stack strings, where four byte chunks are PUSH'd to the stack. There are stackpushnull and stackpushdoublenull to create mutations where the string is single or double null terminated.
- fallchill - Custom string encoding routine used by Lazarus (aka HIDDEN COBRA) in FALLCHILL malware [[ref tweet](https://twitter.com/stvemillertime/status/1485990404948381698)]
- reverse - Simple reverse strings
- hex - Simple "hexidecimal values in a string form.

## Lists

We compiled a couple of lists of Windows DLL and function names by cherry picking subsets of the Windows API. 
- Windows API index: https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list

We recommend evaluating these, breaking them into sensible buckets (such as by their associated utility), and experimenting to find out which sets work well in rules. Add additional ones, or other file or function names that may not be listed here. 

## Cerebro File Usage Example

Use the script take the list of newline separated strings and mutate those using the flipflop function and print them into YARA terms. You can jam these into YARA rules, or expand the script to print them out in different ways or forms that are most easily useful for you. Have fun fiddling!

```

steve@CFO-MBP % python cerebro-file-basic.py --mutation flipflop --file common_windows_dlls.txt

        $kernel32dll_flipflop = "eknrle23d.ll" nocase
        $ws2_32dll_flipflop = "sw_223d.ll" nocase
        $msvcrtdll_flipflop = "smcvtrd.ll" nocase
        $kernelbasedll_flipflop = "eknrleabesd.ll" nocase
        $advapi32dll_flipflop = "daavip23d.ll" nocase
        $advapires32dll_flipflop = "daaviper3s.2ldl" nocase
        $gdi32dll_flipflop = "dg3i.2ldl" nocase
        $gdiplusdll_flipflop = "dgpiul.sldl" nocase
        $win32ksys_flipflop = "iw3nk2s.sy" nocase
        $user32dll_flipflop = "sure23d.ll" nocase
        $comctl32dll_flipflop = "occmlt23d.ll" nocase
        $commdlgdll_flipflop = "ocmmld.gldl" nocase
        $comdlg32dll_flipflop = "ocdmgl23d.ll" nocase
        $commctrldll_flipflop = "ocmmtclrd.ll" nocase
        $shelldll_flipflop = "hsle.lldl" nocase
        $shell32dll_flipflop = "hsle3l.2ldl" nocase
        $shlwapidll_flipflop = "hswlpa.ildl" nocase
        $netapi32dll_flipflop = "enatip23d.ll" nocase
        $shdocvwdll_flipflop = "hsodvc.wldl" nocase
        $mshtmldll_flipflop = "smthlmd.ll" nocase
        $urlmondll_flipflop = "rumlnod.ll" nocase
        $iphlpapidll_flipflop = "pilhapipd.ll" nocase
        $httpapidll_flipflop = "thptpa.ildl" nocase
        $msvbvm60dll_flipflop = "smbvmv06d.ll" nocase
        $shfolderdll_flipflop = "hsofdlred.ll" nocase
        $ole32dll_flipflop = "lo3e.2ldl" nocase
        $wininetdll_flipflop = "iwinen.tldl" nocase
        $wsock32dll_flipflop = "swco3k.2ldl" nocase
```


## Cerebro String Usage Example

```

CTO-MBP\steve >> python3 cerebro-string-basic.py -s netapi32.dll -m all

        $netapi32dll_flipflop = "enatip23d.ll" nocase
        $netapi32dll_reverse = "lld.23ipaten" nocase
        $netapi32dll_hex_enc_str = "6e657461706933322e646c6c" nocase
        $netapi32dll_fallchill = "mvgakr32.woo" nocase
        $netapi32dll_stackpush = "h.dllhpi32hneta" nocase
        $netapi32dll_stackpushnull = "h.dll\x00hpi32hneta"
        $netapi32dll_stackpushdoublenull = "h.dll\x00\x00hpi32hneta"
```