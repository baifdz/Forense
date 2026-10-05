
Artefactos de Dispositivos Extraíbles (USB)

Historial de dispositivos USB conectados (Registro USBSTOR):
~~~cmd
reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR /s
~~~

Marca de tiempo exacta de conexión (Kernel-PnP):
~~~cmd
wevtutil qe System /q:"*[System[Provider[@Name='Microsoft-Windows-Kernel-PnP'] and (EventID=400 or EventID=410)]]" /c:15 /f:text
~~~

Detección de carpetas ocultas por el malware en el USB:
~~~cmd
:: 1. Ver qué letra tienen asignados los discos extraíbles
wmic logicaldisk where drivetype=2 get deviceid, volumename

:: 2. Buscar archivos ocultos (Reemplaza E:\ con la letra encontrada)
dir /a /s "E:\"
~~~

Rastros de Interacción del Usuario
Historial de accesos directos (Archivos LNK recientes en todos los perfiles):


~~~cmd

for /D %U in ("C:\Users\*") do @dir /a /o:-d "%U\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" 2>nul
~~~

Evidencia de ejecución histórica (Archivos Prefetch ordenados por fecha):
~~~cmd
dir /a /o:-d "C:\Windows\Prefetch\*.pf"
~~~

Trazabilidad de Procesos (Equivalentes a Process Explorer/Monitor)
Eventos de creación de procesos generales (Event ID 4688):
~~~cmd
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /c:50 /f:text
~~~

Búsqueda de ejecuciones provenientes directamente de letras de USB (D:\ a Z:):
~~~cmd
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text | findstr /R /C:"[D-Z]:\\"
~~~


Árbol de procesos hijo generado por el malware:

~~~cmd
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text | findstr /i "malware.exe"
~~~

Búsqueda de Persistencia

Búsqueda masiva de ejecutables/scripts creados en los últimos 3 días:
~~~cmd
forfiles /P "C:\Users" /S /M *.exe /D -3 /C "cmd /c echo @path @fdate @ftime" 2>nul
~~~

Si quieres buscar todas las extensiones sospechosas sin filtrar por fecha (para una vista general rápida):

~~~cmd
dir /s /a /b "C:\Users\*.exe" "C:\Users\*.dll" "C:\Users\*.vbs" "C:\Users\*.bat" "C:\Users\*.ps1"
~~~

Revisión de llaves de registro de auto-arranque (Run Keys):
~~~cmd
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
~~~
Acciones Auxiliares Forenses

Extracción de Hash SHA-256 para Inteligencia de Amenazas:

~~~cmd
certutil -hashfile "C:\Users\USUARIO\Desktop\malware.exe" SHA256
~~~

Comprobación de limpieza de Escritorio (Archivos ocultos locales):
~~~cmd
dir /a "C:\Users\USUARIO\Desktop"
~~~

Generación de volcado de memoria de un proceso (Minidump nativo):

~~~cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Users\Public\dump.bin full
~~~















