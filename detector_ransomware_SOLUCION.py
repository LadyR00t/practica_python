import os
import re
import time
import math
import shutil
from pathlib import Path
from datetime import datetime


# =========================
# 1. CONFIGURACIÓN GLOBAL
# =========================

# Ruta base que queremos analizar
RUTA_BASE = Path(r"/Compartido")

# Carpeta de cuarentena donde moveremos los ficheros sospechosos
RUTA_CUARENTENA = Path(r"/cuarentena_ransomware")

# Tamaño máximo de bytes a leer por fichero para calcular entropía (ej: 64 KB)
MAX_BYTES_LECTURA = 64 * 1024

# Umbral de entropía a partir del cual consideramos el fichero sospechoso
UMBRAL_ENTROPIA = 7.5

# Expresión regular para extensiones sospechosas de ransomware
PATRON_EXTENSION_SOSPECHOSA = re.compile(
    r"\.(locked|encrypted|crypto|enc|encrypted_\w+|deadbolt)$",
    re.IGNORECASE
)


# =========================
# 2. FUNCIONES AUXILIARES
# =========================

def calcular_entropia(ruta_fichero):
    """
    Calcula una entropía aproximada del contenido de un fichero.
    Lee como máximo MAX_BYTES_LECTURA bytes.
    Devuelve un float (entropía en bits por byte).
    Si no se puede leer, devuelve None.
    """
    try:
        with ruta_fichero.open("rb") as f:
            datos = f.read(MAX_BYTES_LECTURA)
    except (OSError, IOError):
        return None

    if not datos:
        return 0.0

    # Contar frecuencia de cada byte (0-255)
    frecuencias = [0] * 256
    for b in datos:
        frecuencias[b] += 1

    entropia = 0.0
    longitud = len(datos)

    for freq in frecuencias:
        if freq == 0:
            continue
        p = freq / longitud
        entropia -= p * math.log2(p)

    return entropia


def extension_sospechosa(ruta_fichero):
    """
    Devuelve True si la extensión del fichero coincide
    con el patrón de extensiones sospechosas.
    """
    nombre = ruta_fichero.name
    return bool(PATRON_EXTENSION_SOSPECHOSA.search(nombre))


def analizar_fichero(ruta_fichero):
    """
    Analiza un fichero y devuelve un diccionario con información:
    {
      'ruta': str,
      'tamano': int,
      'entropia': float o None,
      'motivos': [ 'extension', 'entropia' ]
    }
    Si no es sospechoso, devuelve None.
    """
    motivos = []

    # Comprobar extensión
    if extension_sospechosa(ruta_fichero):
        motivos.append("extension")

    # Calcular entropía
    entropia = calcular_entropia(ruta_fichero)
    if entropia is not None and entropia >= UMBRAL_ENTROPIA:
        motivos.append("entropia")

    if not motivos:
        return None

    try:
        tamano = ruta_fichero.stat().st_size
    except (OSError, IOError):
        tamano = -1

    return {
        "ruta": str(ruta_fichero),
        "tamano": tamano,
        "entropia": entropia,
        "motivos": motivos
    }


def recorrer_directorio():
    """
    Recorre el árbol de directorios en RUTA_BASE
    y devuelve una lista de ficheros sospechosos.
    """
    sospechosos = []

    for carpeta, subcarpetas, archivos in os.walk(RUTA_BASE):
        carpeta_path = Path(carpeta)
        for nombre_archivo in archivos:
            ruta_fichero = carpeta_path / nombre_archivo

            # Puedes ignorar ciertos tipos de ficheros si quieres
            # Por ejemplo, no tiene mucho sentido analizar .jpg, .png, etc.
            if ruta_fichero.suffix.lower() in [".jpg", ".jpeg", ".png", ".gif"]:
                continue

            info = analizar_fichero(ruta_fichero)
            if info:
                sospechosos.append(info)

    return sospechosos


def mover_a_cuarentena(sospechosos):
    """
    Mueve los ficheros sospechosos a RUTA_CUARENTENA.
    Devuelve una lista de rutas destino.
    """
    if not RUTA_CUARENTENA.exists():
        RUTA_CUARENTENA.mkdir(parents=True, exist_ok=True)

    destinos = []

    for info in sospechosos:
        origen = Path(info["ruta"])
        destino = RUTA_CUARENTENA / origen.name

        # Evitar sobreescribir si ya existe
        if destino.exists():
            # Le añadimos un sufijo con timestamp
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            destino = RUTA_CUARENTENA / f"{destino.stem}_{timestamp}{destino.suffix}"

        try:
            shutil.move(str(origen), str(destino))
            destinos.append(str(destino))
        except (OSError, IOError) as e:
            print(f"[!] Error al mover {origen} a cuarentena: {e}")

    return destinos


def mostrar_informe(sospechosos, inicio, fin):
    """
    Muestra por pantalla:
    - fecha/hora de ejecución
    - tabla de ficheros sospechosos
    - número total
    - duración en segundos (redondeada hacia arriba)
    """
    ahora = datetime.now()
    duracion = fin - inicio

    print("-" * 80)
    print(f"Fecha de análisis: {ahora.day}/{ahora.month}/{ahora.year} "
          f"{ahora.hour:02d}:{ahora.minute:02d}:{ahora.second:02d}")
    print()

    if not sospechosos:
        print("No se han encontrado ficheros sospechosos en el directorio analizado.")
        print(f"Duración del análisis: {math.ceil(duracion)} segundos")
        print("-" * 80)
        return

    # Cabecera de la tabla
    print(f"{'Tamaño (bytes)':<15} {'Entropía':<10} {'Motivos':<20} Ruta")
    print("-" * 80)

    for info in sospechosos:
        tam = info["tamano"]
        ent = f"{info['entropia']:.2f}" if info["entropia"] is not None else "N/A"
        motivos = ",".join(info["motivos"])
        ruta = info["ruta"]
        print(f"{tam:<15} {ent:<10} {motivos:<20} {ruta}")

    print()
    print(f"Ficheros sospechosos encontrados: {len(sospechosos)}")
    print(f"Duración del análisis: {math.ceil(duracion)} segundos")
    print("-" * 80)


# =========================
# 3. PUNTO DE ENTRADA
# =========================

if __name__ == "__main__":
    inicio = time.time()

    sospechosos = recorrer_directorio()
    destinos = mover_a_cuarentena(sospechosos)

    fin = time.time()

    mostrar_informe(sospechosos, inicio, fin)

    if destinos:
        print("\nFicheros movidos a cuarentena:")
        for d in destinos:
            print(f" - {d}")
