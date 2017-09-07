# APC for the Win(dows)

This is sample code for the technique described in the article [**APC for the Win(dows)**](https://stolenbytes.com/?p=32)

To build and test code you will need **Visual Studio Build tools** 2013, 2015 or 2017, either standalone or one integrated with Visual Studio, and **cmake**:

* [Visual C++ 2015 Build tools](http://landinghub.visualstudio.com/visual-cpp-build-tools)
* [Build Tools for Visual Studio 2017](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017)
* [cmake](https://cmake.org/)

Use the vcvarsall.bat from Build tools, navigate to the folder where you have cloned this repository and type (if cmake.exe is in your %PATH%).

To compile apcforthewin32.exe:
```
vcvarsall.bat x86
cmake.bat
```

To compile apcforthewin64.exe:
```
vcvarsall.bat x64
cmake.bat
```

This will compile **apcforthewin32.exe** or **apcforthewin64.exe** in **build** folder depending on which build console you have used. 

apcforthewin32 in x64 Windows, run from Explorer: \windows\syswow64\notepad.exe
```
build\apcforthewin32.exe notepad.exe
```

apcforthewin64 in x64 Windows, run from Explorer: \windows\system32\notepad.exe
```
build\apcforthewin64.exe notepad.exe
```

apcforthewin32 in x32 Windows, run from Explorer: \windows\system32\notepad.exe
```
build\apcforthewin32.exe notepad.exe
```

Of course, you may specify any process name on the command line.

apcforthewin32.exe must be used with x32 processes and apcforthewin64.exe must be used with x64 processes.

It is possible use the -L param for a infinite find of an alertable thread:
```
apcforthewin32.exe notepad.exe
[X] Failed to find alertable thread... meeh... use -L param for a infinite find and Ctrl^C to exit.
apcforthewin32.exe notepad.exe -L
[X] Failed to find alertable thread... meeh... use -L param for a infinite find and Ctrl^C to exit.
[X] Failed to find alertable thread... meeh... use -L param for a infinite find and Ctrl^C to exit.
[X] Failed to find alertable thread... meeh... use -L param for a infinite find and Ctrl^C to exit.
[*] Alertable thread     : 4352
[*] Shellcode len        : 263
[*] Found rwx dll at     : C:\Windows\assembly\NativeImages_v2.0.50727_32\Microsoft.Ink\fca85cbe6f81c5f7c9b0d87f7c511bd7\Microsoft.Ink.ni.dll
[*] Found write offset at: 75350B4C
[*] Found rwx offset at  : 00044000
[*] Done...
```

Note: you should need open some menu options in Notepad while the find is working.
