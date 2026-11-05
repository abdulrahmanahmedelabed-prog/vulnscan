@echo off
rem vulnscan — انقر مرتين لتشغيل الواجهة الرسومية. يحتاج Python 3.
setlocal
cd /d "%~dp0"
set "PY="
for %%C in (py python python3) do (
  if not defined PY (
    %%C -c "import sys" >nul 2>nul && set "PY=%%C"
  )
)
if not defined PY (
  echo.
  echo  Python 3 غير مثبّت.
  echo  ثبّته من https://www.python.org/downloads/ ^(فعّل خيار Add to PATH^) ثم شغّل هذا الملف مجددًا.
  echo.
  pause
  exit /b 1
)
echo  يبدأ تشغيل vulnscan... سيفتح المتصفح تلقائيًا. اترك هذه النافذة مفتوحة.
echo  للإيقاف: اضغط Ctrl+C أو أغلق النافذة.
%PY% -m vulnscan ui
if errorlevel 1 (
  echo.
  echo  تعذّر التشغيل. تأكد أنك فككت ضغط المجلد كاملًا وأن Python 3 مثبّت.
  pause
)
