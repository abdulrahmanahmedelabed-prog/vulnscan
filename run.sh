#!/usr/bin/env bash
# vulnscan — شغّل الواجهة الرسومية. يحتاج Python 3.
cd "$(dirname "$0")" || exit 1
for PY in python3 python py; do
  if command -v "$PY" >/dev/null 2>&1; then
    echo "يبدأ تشغيل vulnscan... سيفتح المتصفح تلقائيًا. للإيقاف اضغط Ctrl+C."
    exec "$PY" -m vulnscan ui
  fi
done
echo "Python 3 غير مثبّت. ثبّته من https://www.python.org/downloads/ ثم أعد المحاولة." >&2
exit 1
