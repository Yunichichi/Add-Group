ADLookupApi - Paquete de Lookup de Grupo de Active Directory (Profesional)
===========================================================================

Descripción
-----------
Aplicación web para consultar miembros de un grupo de Active Directory. Incluye:
- Interfaz moderna con selector de idioma (ES/EN/PT).
- Opciones avanzadas: incluir email, PrimaryGroup, miembros anidados, cuentas deshabilitadas, atributos extra.
- Descarga CSV o visualización JSON tabular.
- Opción de guardar el archivo también en el servidor.
- Consola de comandos para ejecutar/ajustar parámetros rápidamente y filtrar resultados.
- Botón de reinicio para limpiar y re-ejecutar.

Estructura
----------
ADLookupApi/
  index.html
  api/
    grouplookup.ps1
  web.config
  README.txt

Requisitos
----------
- Windows Server con Active Directory accesible.
- RSAT / Módulo ActiveDirectory de PowerShell.
- IIS instalado con permisos para ejecutar scripts PowerShell (.ps1).
- Application Pool con permisos mínimos necesarios para leer AD y escribir en la carpeta de salida (si se usa).

Instalación
-----------
1) Copia la carpeta `ADLookupApi` a tu sitio IIS, por ejemplo:
   C:\inetpub\wwwroot\ADLookupApi

2) Verifica el handler en `web.config`:
   - Ajusta la ruta a powershell.exe si es distinta.
   - Asegúrate que la extensión .ps1 no esté bloqueada por Request Filtering.

3) Pool de la aplicación:
   - Establece la identidad con permisos de lectura en AD y de escritura en la ruta de salida (si se usa).
   - Permite ejecución de scripts: ExecutionPolicy adecuado (ej. Bypass en el handler).

4) Navega a:
   http://tu-servidor/ADLookupApi/index.html

Uso de la consola
-----------------
Comandos soportados (también en inglés/portugués si cambias idioma):
  /help                         - Mostrar ayuda
  /lang es|en|pt               - Cambiar idioma
  /group NOMBRE                - Establecer nombre de grupo
  /format csv|json             - Formato de salida
  /includeEmail on|off         - Incluir email
  /includePrimary on|off       - Incluir PrimaryGroup
  /includeNested on|off        - Incluir miembros anidados
  /includeDisabled on|off      - Incluir deshabilitados
  /out RUTA                    - Ruta de salida en servidor
  /save on|off                 - Guardar también en servidor
  /filter TEXTO                - Filtrar resultados (solo JSON) por texto
  /run                         - Ejecutar búsqueda
  /clear                       - Reiniciar interfaz

Notas técnicas
--------------
- El frontend envía POST JSON a /api/grouplookup.ps1. El script soporta parámetros desde JSON o desde línea de comandos.
- Salida:
  * JSON: Content-Type application/json
  * CSV: Content-Type text/csv + Content-Disposition: attachment
- Si se marca "Guardar en servidor" y se especifica ruta, se guarda el archivo (CSV/JSON) y el servidor envía cabecera `X-Saved-Path` con la ubicación final.
- Atributos extra: utiliza Get-ADUser -Properties con la unión de propiedades base + seleccionadas.

Seguridad recomendada
---------------------
- Habilita autenticación (p. ej., Windows Authentication) en la carpeta del sitio y/o el endpoint.
- Limita permisos de la identidad del Application Pool (principio de privilegio mínimo).
- No expongas el endpoint públicamente sin controles.
- Considera registrar auditoría de accesos.

Resolución de problemas
-----------------------
- 404 para .ps1: revisa Handler Mappings y Request Filtering; valida web.config en la carpeta.
- 500/errores de ejecución: valida ExecutionPolicy, RSAT y módulo ActiveDirectory.
- CSV vacío: valida que el grupo existe y tiene usuarios; revisa filtros (deshabilitados, etc.).
- No guarda en servidor: revisa permisos NTFS sobre la ruta y que exista o pueda crearse.