# 🧩 Enunciado del ejercicio

## Título

**Detección de ficheros potencialmente cifrados por ransomware en un recurso compartido**

## Contexto

En una organización se ha detectado comportamiento anómalo en un recurso compartido de red utilizado por varios departamentos. Algunos usuarios reportan que ciertos documentos han dejado de abrirse y que han aparecido extensiones de archivo extrañas.

Se sospecha que pueda tratarse de una actividad de tipo ransomware, que cifra ficheros y cambia sus extensiones.

Tu tarea consiste en implementar un script en Python que ayude a identificar posibles ficheros cifrados y a aislarlos para su posterior análisis.

## Objetivos

Desarrollar un programa en Python que:

- Recorra recursivamente todas las carpetas y subcarpetas a partir de una ruta base (por ejemplo, `C:\Users\<usuario>\Desktop\Compartido` o una ruta equivalente en tu sistema).

- Analice cada fichero y determine si es potencialmente sospechoso de estar cifrado, utilizando dos criterios:
  - **Extensión sospechosa** (típicas de ransomware o no habituales, por ejemplo: `.locked`, `.encrypted`, `.crypto`, `.enc`, etc.).
  - **Alta entropía del contenido** (muy aleatorio), característica habitual de ficheros cifrados.

- Genere un informe por consola que incluya:
  - Fecha y hora de la ejecución.
  - Una tabla con los ficheros marcados como sospechosos, mostrando:
    - Ruta completa del fichero
    - Tamaño en bytes
    - Entropía aproximada
    - Motivos por los que ha sido marcado ("extension", "entropia" o ambas)
  - El número total de ficheros sospechosos.
  - La duración del análisis en segundos, redondeada hacia arriba.

- Mueva los ficheros sospechosos a una carpeta de cuarentena (por ejemplo, `cuarentena_ransomware` en el escritorio), para evitar que sigan disponibles en el recurso compartido mientras el equipo de respuesta los analiza.

## Requisitos técnicos

Debes utilizar, al menos, las siguientes librerías estándar de Python:

- `os` y `pathlib.Path` para recorrer directorios y manejar rutas.
- `re` para detectar extensiones sospechosas mediante expresiones regulares.
- `time` para medir la duración del análisis.
- `datetime` para mostrar la fecha y hora de ejecución.
- `math` para:
  - Calcular entropía (usando `math.log2`).
  - Redondear hacia arriba los segundos de duración (`math.ceil`).
- `shutil` para mover ficheros a la carpeta de cuarentena.

## Detalles de implementación

### Recorrido de directorios

- Usa `os.walk()` para recorrer el árbol completo a partir de la ruta base.
- Combina con `Path` para construir rutas (`Path(carpeta) / nombre_archivo`).

### Detección por extensión

- Define un patrón de regex que considere extensiones sospechosas, por ejemplo:
  - `.locked`, `.encrypted`, `.crypto`, `.enc`, etc.
- El programa debe ser fácilmente extensible para añadir nuevas extensiones.

### Cálculo de entropía

- Abre el fichero en modo binario.
- Lee como máximo un número limitado de bytes (por ejemplo, 64 KB) para no penalizar demasiado el rendimiento.
- Cuenta la frecuencia de cada byte (0–255) y calcula la entropía aproximada con:

  **H = −∑pᵢ log₂(pᵢ)**

- Determina un umbral (por ejemplo, H > 7.5) a partir del cual considerar el fichero sospechoso por entropía.

### Criterio final de sospecha

Marca un fichero como sospechoso si:

- Tiene extensión sospechosa, **o**
- Su entropía es mayor o igual al umbral configurado.

Guarda para cada fichero sospechoso:

- Ruta completa
- Tamaño
- Entropía calculada
- Lista de motivos (`["extension"]`, `["entropia"]` o `["extension", "entropia"]`).

### Informe

Muestra por consola:

- Fecha y hora de ejecución en formato legible.
- Una tabla con columnas alineadas:
  - Tamaño (bytes)
  - Entropía
  - Motivos
  - Ruta
- Número total de ficheros sospechosos.
- Duración del análisis en segundos (redondeado hacia arriba con `math.ceil`).

### Cuarentena

- Crea la carpeta de cuarentena si no existe.
- Mueve ahí los ficheros sospechosos usando `shutil.move`.
- Si un fichero con el mismo nombre ya existe en la cuarentena, añade un sufijo con timestamp para evitar sobrescribirlo.

