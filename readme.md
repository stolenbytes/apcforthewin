# APC for the Win(dows)

This is sample code for the technique described in the article **APC for the Win(dows)**.

To build and test code you will need **Visual Studio Build tools** 2013, 2015 or 2017, either standalone or one integrated with Visual Studio, and **cmake**:

* [Visual C++ 2015 Build tools](http://landinghub.visualstudio.com/visual-cpp-build-tools)
* [Build Tools for Visual Studio 2017](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017)
* [cmake](https://cmake.org/)

Navigate to the folder where you have cloned this repository from Build tools command prompt and type (if cmake.exe is in your %PATH%):

```
cmake.bat
```

This will compile **apcforthewin32.exe** or **apcforthewin64.exe** in **build** folder depending on which build console you have used.

Now run:
```
build\apcforthewin32/64.exe calc.exe
```

If **calc.exe** is running you will get nice messagebox from it. Of course, you may specify any process name on the command line.
