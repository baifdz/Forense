Artefactos de Dispositivos Extraíbles (USB)
Historial de dispositivos USB conectados (Registro USBSTOR):
~~~powershell
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | Select-Object PSChildName | Format-Table -AutoSize | Out-String
~~~

Marca de tiempo exacta de conexión (Kernel-PnP):
~~~powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-PnP'; ID=400,410} -MaxEvents 15 | Select-Object TimeCreated, Message | Format-Table -AutoSize -Wrap | Out-String
~~~

Detección de carpetas ocultas por el malware en el USB:
~~~powershell
Get-Volume | Where-Object DriveType -eq 'Removable' | ForEach-Object { Get-ChildItem -Path "\((\)_.DriveLetter):\" -Force | Select-Object FullName, Attributes, @{N='Tamaño(MB)';E={[math]::Round($_.Length / 1MB, 2)}} } | Format-Table -AutoSize -Wrap | Out-String
~~~

Rastros de Interacción del Usuario
Historial de accesos directos (Archivos LNK recientes):
~~~powershell
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name, LastWriteTime | Format-Table -AutoSize | Out-String
~~~

Evidencia de ejecución histórica (Archivos Prefetch):
~~~powershell
Get-ChildItem -Path "C:\Windows\Prefetch\*.pf" | Sort-Object LastWriteTime -Descending | Select-Object -First 30 Name, LastWriteTime, CreationTime | Format-Table -AutoSize | Out-String
~~~

Trazabilidad de Procesos (Equivalentes a Process Explorer/Monitor)
Eventos de creación de procesos generales (Event ID 4688):
~~~powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50 | Select-Object TimeCreated, @{N='Process';E={\(_.Properties[5].Value}}, @{N='CommandLine';E={\)_.Properties[8].Value}} | Format-Table -AutoSize -Wrap | Out-String
~~~

Búsqueda de ejecuciones provenientes directamente de letras de USB (D:\ a Z:\):
~~~powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { \(_.Properties[5].Value -match "^[D-Z]:\\" } | Select-Object TimeCreated, @{N='Process';E={\)_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}} | Format-Table -AutoSize -Wrap | Out-String
~~~

Árbol de procesos hijo generado por el malware:
~~~powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 2000 -ErrorAction SilentlyContinue | Where-Object { \(_.Properties[13].Value -match "malware.exe" } | Select-Object TimeCreated, @{N='Hijo_Creado';E={\)_.Properties[5].Value}}, @{N='Comando_Ejecutado';E={$_.Properties[8].Value}} | Format-Table -AutoSize -Wrap | Out-String
~~~

Búsqueda de Persistencia
Búsqueda masiva en todos los perfiles de usuario (Temp, AppData, Local, Public):
~~~powershell
Get-ChildItem -Path 'C:\Users\*\AppData\Local\Temp', 'C:\Users\*\AppData\Roaming', 'C:\Users\*\AppData\Local', 'C:\Users\Public' -Include *.exe,*.dll,*.vbs,*.bat,*.ps1 -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-3) } | Select-Object FullName, CreationTime | Format-Table -AutoSize -Wrap | Out-String
~~~

Revisión de llaves de registro de auto-arranque (Run Keys):
~~~powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Format-List | Out-String
~~~

Acciones Auxiliares Forenses
Extracción de Hash SHA-256 para Inteligencia de Amenazas:
~~~powershell
Get-FileHash -Path "C:\Users\USUARIO\Desktop\malware.exe" -Algorithm SHA256 | Format-List | Out-String
~~~

Comprobación de limpieza de Escritorio (Archivos ocultos locales):
~~~powershell
Get-ChildItem -Path "C:\Users\USUARIO\Desktop" -Force | Select-Object Name, Attributes | Format-Table -AutoSize | Out-String
~~~

Generación de volcado de memoria de un proceso (Minidump nativo vía RTR):
~~~powershell
Start-Process rundll32.exe -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump  C:\Users\Public\dump.bin full" -Wait
~~~


