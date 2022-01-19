# Cerebro

Scripts and lists to help you brute force YARA friendly string mutations.

# Usage Example

Use the script take the list of newline separated strings and mutate those using the flipflop function and print them into YARA terms. You can jam these into YARA rules, or expand the script to print them out in different ways or forms that are most easily useful for you.

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


