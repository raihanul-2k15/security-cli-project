@echo off

REM Make it a .bat file -> _compile.bat

"C:\Program Files (x86)\CodeBlocks\MinGW\bin\g++" crypto.c rsa.c bruteforce.cpp  ./lib/libgmp.a -o ./release/crypto.exe