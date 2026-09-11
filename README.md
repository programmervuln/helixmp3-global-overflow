# Helix‑MP3‑Decoder Global Buffer Overflow Vulnerability

## Summary
A global buffer overflow (**CWE‑121**) vulnerability exists in the underlying libhelix MP3 decoder core.
When decoding a maliciously constructed MPEG1 intensity stereo MP3 frame, insufficient index bounds checking in `xmp3_IntensityProcMPEG1()` causes an out‑of‑bounds read from the global lookup table `xmp3_ISFMpeg1` / `xmp3_ISFMpeg2` defined inside `trigtabs.c`.
This flaw exists in the core libhelix decoder, triggered via the `helix_mp3.c` wrapper library.
Processing untrusted malicious MP3 input can lead to denial‑of‑service; the out‑of‑bounds read may leak sensitive memory information.
This is an out‑of‑bounds **read** vulnerability, not an out‑of‑bounds write. Arbitrary code execution is not demonstrated.

## Affected component
- Source file: `src/libhelix/real/stproc.c`
- Vulnerable function: `xmp3_IntensityProcMPEG1()`
- Global lookup tables: `xmp3_ISFMpeg1`, `xmp3_ISFMpeg2` in `src/libhelix/real/trigtabs.c`
- Trigger entrypoint: `MP3Decode()`, invoked from `helix_mp3_decode_next_frame()` in `src/helix_mp3.c`

## Vulnerable Code Snippet
Upstream source link: https://github.com/Lefucjusz/Helix-MP3-Decoder/blob/master/src/libhelix/real/stproc.c

```c
// src/libhelix/real/stproc.c
isf = sfis->l[cb];
...
isfTab = (int *)ISFMpeg1[midSideFlag];
fl = isfTab[isf];	// no boundary check
fr = isfTab[6] - isfTab[isf];
Global table definition file:
https://github.com/Lefucjusz/Helix-MP3-Decoder/blob/master/src/libhelix/real/trigtabs.c

fuller vulnerable code:
```c
isf = sfis->l[cb];          /* isf parsed from MP3 bitstream, fully attacker‑controlled */
isfTab = (int *)ISFMpeg1[midSideFlag];

if (isf == 7) {
    fl = ISFIIP[midSideFlag][0];
    fr = ISFIIP[midSideFlag][1];
} else {
    fl = isfTab[isf];	    /* no bounds check: out‑of‑bounds read if isf > 6 */
    fr = isfTab[6] - isfTab[isf];
}

The isf index value is parsed directly from the MP3 frame bitstream without validation.
A malicious MPEG1 intensity stereo MP3 frame can cause isf + i to exceed the size of xmp3_ISFMpeg1 (array size = 56), triggering global buffer out‑of‑bounds read.
Reproduction steps
Build fuzz target fuzz_helix compiled with AddressSanitizer.
Run against the provided crash PoC sample:

ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer) ./fuzz_helix crash‑8b25d5b5d476e85c39600fd2c8582381511a6761 2>&1 > helix_global_symbolized.txt

Repository contents
crash‑8b25d5b5d476e85c39600fd2c8582381511a6761: Malicious PoC MP3 crash sample
helix_global_symbolized.txt: Full symbolized ASAN crash report

ASAN Crash Report

ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer) ./fuzz_helix ./crash-8b25d5b5d476e85c39600fd2c8582381511a6761 2>&1 > helix_global_symbolized.txt
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3864037991
INFO: Loaded 1 modules   (685 inline 8-bit counters): 685 [0x55f5e48e9e00, 0x55f5e48ea0ad),
INFO: Loaded 1 PC tables (685 PCs): 685 [0x55f5e48ea0b0,0x55f5e48ecb80),
./fuzz_helix: Running 1 inputs 1 time(s) each.
Running: ./crash-8b25d5b5d476e85c39600fd2c8582381511a6761
=================================================================
==6438==ERROR: AddressSanitizer: global-buffer-overflow on address 0x55f5e48bd358 at pc 0x55f5e489cf4f bp 0x7ffcf89c78f0 sp 0x7ffcf89c78e8
READ of size 4 at 0x55f5e48bd358 thread T0
    #0 0x55f5e489cf4e in xmp3_IntensityProcMPEG1 /home/lloyd/Documents/Helix-MP3-Decoder-master/src/libhelix/real/stproc.c:146:9
    #1 0x55f5e487bff6 in xmp3_Dequantize /home/lloyd/Documents/Helix-MP3-Decoder-master/src/libhelix/real/dequant.c:139:4
    #2 0x55f5e486ce73 in MP3Decode /home/lloyd/Documents/Helix-MP3-Decoder-master/src/libhelix/mp3dec.c:444:7
    #3 0x55f5e4868947 in helix_mp3_decode_next_frame /home/lloyd/Documents/Helix-MP3-Decoder-master/src/helix_mp3.c:92:25
    #4 0x55f5e4867a10 in helix_mp3_init /home/lloyd/Documents/Helix-MP3-Decoder-master/src/helix_mp3.c:174:13
    #5 0x55f5e48a1657 in LLVMFuzzerTestOneInput /home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix.c:37:15
    #6 0x55f5e4790383 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix+0x43383) (BuildId: 53130c742e027904d21afd0744306946b26023ae)
    #7 0x55f5e477a0ff in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix+0x2d0ff) (BuildId: 53130c742e027904d21afd0744306946b26023ae)
    #8 0x55f5e477fe56 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix+0x32e56) (BuildId: 53130c742e027904d21afd0744306946b26023ae)
    #9 0x55f5e47a9c72 in main (/home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix+0x5cc72) (BuildId: 53130c742e027904d21afd0744306946b26023ae)
    #10 0x7e76da629d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #11 0x7e76da629e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #12 0x55f5e47749c4 in _start (/home/lloyd/Documents/Helix-MP3-Decoder-master/src/fuzz_helix+0x279c4) (BuildId: 53130c742e027904d21afd0744306946b26023ae)

0x55f5e48bd358 is located 8 bytes to the left of global variable 'xmp3_ISFMpeg2' defined in 'libhelix/real/trigtabs.c:182:11' (0x55f5e48bd360) of size 256
0x55f5e48bd358 is located 32 bytes to the right of global variable 'xmp3_ISFMpeg1' defined in 'libhelix/real/trigtabs.c:160:11' (0x55f5e48bd300) of size 56
SUMMARY: AddressSanitizer: global-buffer-overflow /home/lloyd/Documents/Helix-MP3-Decoder-master/src/libhelix/real/stproc.c:146:9 in xmp3_IntensityProcMPEG1
Shadow bytes around the buggy address:
  0x0abf3c90fa10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0abf3c90fa20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0abf3c90fa30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0abf3c90fa40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0abf3c90fa50: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
=>0x0abf3c90fa60: 00 00 00 00 00 00 00 f9 f9 f9 f9[f9]00 00 00 00
  0x0abf3c90fa70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0abf3c90fa80: 00 00 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9
  0x0abf3c90fa90: f9 f9 f9 f9 00 00 f9 f9 00 f9 f9 f9 00 00 00 00
  0x0abf3c90faa0: 00 00 00 00 f9 f9 f9 f9 00 00 00 00 00 00 00 00
  0x0abf3c90fab0: 00 00 00 00 00 00 00 04 f9 f9 f9 f9 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==6438==ABORTING
