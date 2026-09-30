# Forense

Repositorio orientado a la recopilación, análisis y documentación de artefactos digitales para investigación forense y respuesta ante incidentes.

## ¿Qué trata este repositorio?

El proyecto reúne comandos y patrones de búsqueda útiles para identificar evidencia de actividad sospechosa en sistemas Windows, con especial foco en:

- dispositivos USB extraíbles
- conexiones de hardware y registros del sistema
- ejecución de procesos y cadenas de creación
- accesos recientes y archivos de entorno del usuario
- persistencia de malware mediante autoarranque
- presencia de artefactos ocultos o sospechosos
- extracción de hashes para análisis de amenazas

La idea es servir como referencia rápida para análisis forense, no como una suite automatizada de investigación completa.

## Estructura del repositorio

```text
Forense/
├── README.md
├── Linux/
│   └── bash_commands.md
└── Windows/
    └── powershell_commands.md
```

### Windows/

En esta carpeta se almacenan comandos de PowerShell para investigar artefactos típicos de un sistema Windows, como:

- USBSTOR y eventos de conexión de dispositivos
- archivos `.lnk` recientes
- archivos `Prefetch`
- eventos de auditoría de creación de procesos (`4688`)
- claves de registro de autoarranque (`Run`)
- carpetas ocultas en dispositivos extraíbles
- hashes SHA-256 de archivos sospechosos
- revisión de persistencia y artefactos del usuario

### Linux/

La carpeta Linux está preparada para incluir comandos o notas relacionadas con análisis forense en entornos Linux, aunque en este momento su contenido puede estar en desarrollo o ser complementario al material de Windows.

## Uso recomendado

Estos comandos son útiles para:

1. revisar la presencia de malware o ejecución sospechosa
2. identificar dispositivos conectados y su historial
3. detectar trazas de actividad del usuario
4. analizar persistencia del sistema
5. apoyar una investigación digital con evidencia técnica

## Importante

> Este repositorio se utiliza con fines de investigación, análisis forense y respuesta ante incidentes, siempre dentro de entornos autorizados y bajo la legislación aplicable.

No debe usarse para monitorear, recopilar datos o invadir sistemas sin consentimiento explícito.



