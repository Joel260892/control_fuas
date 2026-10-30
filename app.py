from datetime import datetime
import os

import streamlit as st
import psycopg2
import bcrypt
import pandas as pd
import io
import plotly.express as px
import subprocess
import numpy as np
from sqlalchemy import create_engine
import random
import tempfile
import glob
from theme import (
    TEMAS_DISPONIBLES,
    get_theme,
    apply_theme_css
)



# --- AQUÍ ARRIBA COLOCAS LAS CREDENCIALES Y RUTAS ---
DB_USER = st.secrets["postgres"]["user"]
DB_NAME = st.secrets["postgres"]["database"]
DB_PASSWORD = st.secrets["postgres"]["password"]

# Rutas de las herramientas de PostgreSQL (Ajusta el "15" si tu versión es diferente)
PG_DUMP_PATH = r"C:\Program Files\PostgreSQL\18\bin\pg_dump.exe"
PSQL_PATH = r"C:\Program Files\PostgreSQL\18\bin\psql.exe"

# Configuración de la página (layout 'centered' ayuda a que el login luzca mejor centrado)
st.set_page_config(page_title="Control de FUAs Observadas", page_icon="📋", layout="wide")

# Ocultar marca/menú de Streamlit manteniendo visible el botón de la barra lateral
hide_streamlit_style = """
    <style>
    /* Ocultar menú superior y pie de página genérico */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Ocultar de forma absoluta cualquier variante del badge flotante inferior */
    .viewerBadge_container__1QSob,
    div.viewerBadge_container__1QSob,
    .styles_viewerBadge__1yG5_,
    a[href*="streamlit.io/cloud"],
    div[class*="viewerBadge"],
    iframe[title="streamlitApp"] {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        pointer-events: none !important;
    }
    
    /* Garantizar que la barra superior mantenga visible el menú lateral */
    header[data-testid="stHeader"] {
        background-color: transparent !important;
        visibility: visible !important;
    }
    
    button[kind="header"] {
        visibility: visible !important;
        display: flex !important;
    }
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# ==========================================
# 1. FUNCIONES DE CONEXIÓN Y BASE DE DATOS
# ==========================================
def init_connection():
    return psycopg2.connect(
        host=st.secrets["postgres"]["host"],
        database=st.secrets["postgres"]["database"],
        user=st.secrets["postgres"]["user"],
        password=str(st.secrets["postgres"]["password"]),
        port=st.secrets["postgres"]["port"]
    )

def validar_login(username, password):
    conn = init_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT dni, username, password_hash, nombre_completo, es_admin, rol FROM usuarios WHERE username = %s AND activo = TRUE;",
            (username,)
        )
        user = cursor.fetchone()
        
        if user:
            dni, db_username, db_password_hash, nombre_completo, es_admin, db_rol = user
            
            es_valida = False
            try:
                es_valida = bcrypt.checkpw(password.encode('utf-8'), db_password_hash.encode('utf-8'))
            except Exception:
                es_valida = (password == db_password_hash)
            
            if es_valida:
                if es_admin:
                    rol_final = "Administrador"
                else:
                    rol_final = db_rol if db_rol else "Digitador"
                    
                return {
                    "dni": str(dni), 
                    "username": str(db_username), 
                    "nombre": str(nombre_completo), 
                    "es_admin": bool(es_admin),
                    "rol": rol_final
                }
        return None
    except Exception as e:
        try:
            conn.rollback()
            cursor.execute(
                "SELECT dni, username, password_hash, nombre_completo, es_admin FROM usuarios WHERE username = %s AND activo = TRUE;",
                (username,)
            )
            user = cursor.fetchone()
            if user:
                dni, db_username, db_password_hash, nombre_completo, es_admin = user
                es_valida = bcrypt.checkpw(password.encode('utf-8'), db_password_hash.encode('utf-8')) if 'password_hash' in locals() else (password == db_password_hash)
                if es_valida:
                    return {
                        "dni": str(dni),
                        "username": str(db_username),
                        "nombre": str(nombre_completo),
                        "es_admin": bool(es_admin),
                        "rol": "Administrador" if es_admin else "Digitador"
                    }
        except Exception:
            pass
        st.error(f"Error en la base de datos: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def registrar_nuevo_usuario(dni, username, password, nombre_completo, rol_seleccionado):
    conn = init_connection()
    cur = conn.cursor()
    try:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        es_admin_bool = True if rol_seleccionado == "Administrador" else False
        
        try:
            cur.execute(
                """
                INSERT INTO usuarios (dni, username, password_hash, nombre_completo, es_admin, rol, activo)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE);
                """,
                (dni, username, password_hash, nombre_completo, es_admin_bool, rol_seleccionado)
            )
        except Exception:
            conn.rollback()
            cur.execute(
                """
                INSERT INTO usuarios (dni, username, password_hash, nombre_completo, es_admin, activo)
                VALUES (%s, %s, %s, %s, %s, TRUE);
                """,
                (dni, username, password_hash, nombre_completo, es_admin_bool)
            )
            
        conn.commit()
        return True, "¡Usuario registrado exitosamente!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al registrar: {e}"
    finally:
        cur.close()
        conn.close()

def actualizar_usuario(dni, username, nombre_completo, rol_seleccionado, activo, nueva_password=None):
    conn = init_connection()
    cur = conn.cursor()
    try:
        es_admin_bool = True if rol_seleccionado == "Administrador" else False
        
        if nueva_password and nueva_password.strip() != "":
            password_hash = bcrypt.hashpw(nueva_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            try:
                cur.execute(
                    """
                    UPDATE usuarios 
                    SET username = %s, nombre_completo = %s, es_admin = %s, rol = %s, activo = %s, password_hash = %s
                    WHERE dni = %s;
                    """,
                    (username, nombre_completo, es_admin_bool, rol_seleccionado, activo, password_hash, dni)
                )
            except Exception:
                conn.rollback()
                cur.execute(
                    """
                    UPDATE usuarios 
                    SET username = %s, nombre_completo = %s, es_admin = %s, activo = %s, password_hash = %s
                    WHERE dni = %s;
                    """,
                    (username, nombre_completo, es_admin_bool, activo, password_hash, dni)
                )
        else:
            try:
                cur.execute(
                    """
                    UPDATE usuarios 
                    SET username = %s, nombre_completo = %s, es_admin = %s, rol = %s, activo = %s
                    WHERE dni = %s;
                    """,
                    (username, nombre_completo, es_admin_bool, rol_seleccionado, activo, dni)
                )
            except Exception:
                conn.rollback()
                cur.execute(
                    """
                    UPDATE usuarios 
                    SET username = %s, nombre_completo = %s, es_admin = %s, activo = %s
                    WHERE dni = %s;
                    """,
                    (username, nombre_completo, es_admin_bool, activo, dni)
                )
                
        conn.commit()
        return True, "¡Usuario actualizado exitosamente!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al actualizar: {e}"
    finally:
        cur.close()
        conn.close()

def eliminar_usuario(dni):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM usuarios WHERE dni = %s;", (dni,))
        conn.commit()
        return True, "¡Usuario eliminado correctamente!"
    except Exception as e:
        conn.rollback()
        return False, f"No se puede eliminar porque tiene registros asociados. Te sugerimos desactivarlo."
    finally:
        cur.close()
        conn.close()

def obtener_usuarios():
    conn = init_connection()
    cur = conn.cursor()
    try:
        try:
            cur.execute("SELECT dni, username, nombre_completo, COALESCE(rol, CASE WHEN es_admin THEN 'Administrador' ELSE 'Digitador' END), activo, creado_en FROM usuarios ORDER BY creado_en DESC;")
        except Exception:
            conn.rollback()
            cur.execute("SELECT dni, username, nombre_completo, CASE WHEN es_admin THEN 'Administrador' ELSE 'Digitador' END, activo, creado_en FROM usuarios ORDER BY creado_en DESC;")
        return cur.fetchall()
    except Exception as e:
        return []
    finally:
        cur.close()
        conn.close()


def buscar_afiliado_por_dni(dni_búsqueda):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT dni, nombre, appaterno, apmaterno, fecha_nacimiento
            FROM afiliados
            WHERE TRIM(dni::text) = TRIM(%s);
            """,
            (str(dni_búsqueda),)
        )
        resultado = cur.fetchone()
        return resultado
    except Exception as e:
        st.error(f"Error en la consulta de afiliados: {e}")
        return None
    finally:
        cur.close()
        conn.close()

def obtener_lista_establecimientos():
    conn = init_connection()
    cur = conn.cursor()
    try:
        # Usamos nombre_establecimiento
        cur.execute("SELECT id, nombre_establecimiento FROM establecimientos WHERE activo = TRUE ORDER BY nombre_establecimiento ASC;")
        return cur.fetchall()
    except Exception:
        try:
            cur.execute("SELECT id, nombre_establecimiento FROM establecimientos ORDER BY nombre_establecimiento ASC;")
            return cur.fetchall()
        except Exception:
            return []
    finally:
        cur.close()
        conn.close()

def obtener_lista_profesionales():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT dni, nombres_apellidos, profesion_o_especialidad 
            FROM profesionales 
            WHERE activo = TRUE 
            ORDER BY nombres_apellidos ASC;
            """
        )
        return cur.fetchall()
    except Exception as e:
        st.error(f"Error al obtener profesionales: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def registrar_fua_observada(datos):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id FROM fuas_observadas WHERE TRIM(numero_fua) = TRIM(%s) LIMIT 1;",
            (datos["numero_fua"],)
        )
        if cur.fetchone():
            return False, f"⚠️ El Nº de FUA **{datos['numero_fua']}** ya se encuentra registrado en el sistema."

        # Procesamos la fecha de atención de forma segura:
        # Si es un objeto de fecha válido, lo convertimos a string; si es None o vacío, enviamos None (NULL en la BD)
        f_atencion = datos.get("fecha_atencion_fua")
        fecha_valida = f_atencion.strftime("%Y-%m-%d") if f_atencion else None

        cur.execute(
            """
            INSERT INTO fuas_observadas (
                numero_fua,
                id_prestacion,
                nombre_prestacion,
                establecimiento_id, 
                afiliado_dni, 
                afiliado_nombre, 
                afiliado_appaterno, 
                afiliado_apmaterno, 
                afiliado_fecha_nacimiento, 
                profesional_dni, 
                digitador_dni, 
                tipo_observacion, 
                detalle_observacion, 
                fecha_atencion_fua, 
                estado
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pendiente');
            """,
            (
                datos["numero_fua"],
                datos["id_prestacion"],
                datos["nombre_prestacion"],
                datos["establecimiento_id"],
                datos["afiliado_dni"],
                datos["afiliado_nombre"],
                datos["afiliado_appaterno"],
                datos["afiliado_apmaterno"],
                datos["afiliado_fecha_nacimiento"],
                datos["profesional_dni"],
                datos["digitador_dni"],
                datos["tipo_observacion"],
                datos["detalle_observacion"],
                fecha_valida  # Usamos la variable tratada de forma segura
            )
        )
        conn.commit()
        return True, "¡FUA observada registrada con éxito!"
    except Exception as e:
        conn.rollback()
        if "unique" in str(e).lower() or "duplicad" in str(e).lower():
            return False, f"⚠️ El Nº de FUA **{datos['numero_fua']}** ya existe registrado."
        return False, f"Error al guardar el registro: {e}"
    finally:
        cur.close()
        conn.close()

def obtener_fuas_observadas():
    conn = init_connection() # Asegúrate de obtener la conexión
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 
                f.id,
                f.numero_fua,
                e.nombre_establecimiento AS establecimiento,
                f.afiliado_dni,
                CONCAT(f.afiliado_nombre, ' ', f.afiliado_appaterno, ' ', f.afiliado_apmaterno) AS paciente,
                p.nombres_apellidos AS profesional,
                f.tipo_observacion,
                f.fecha_atencion_fua,
                f.estado,
                f.fecha_registro,
                f.fecha_correccion,
                f.digitador_dni,
                f.id_prestacion
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            LEFT JOIN profesionales p ON f.profesional_dni = p.dni
            ORDER BY f.fecha_registro DESC;
        """)
        return cur.fetchall()
    except Exception as e:
        st.error(f"Error al obtener la bandeja de FUAs: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def actualizar_estado_fua(fua_id, nuevo_estado, dni_usuario=None):
    conn = init_connection()
    cur = conn.cursor()
    try:
        # 1. Obtener número de FUA y estado actual
        cur.execute("SELECT numero_fua, estado FROM fuas_observadas WHERE id = %s;", (fua_id,))
        resultado = cur.fetchone()
        if not resultado:
            return False, "No se encontró la FUA."
        
        numero_fua, estado_anterior = resultado

        # 2. Actualizar estado y fecha de corrección (SIN tocar digitador_dni)
        if nuevo_estado in ["Corregido", "Anulado"]:
            cur.execute(
                """
                UPDATE fuas_observadas 
                SET estado = %s, fecha_correccion = NOW()
                WHERE id = %s;
                """,
                (nuevo_estado, fua_id)
            )
        else:
            cur.execute(
                """
                UPDATE fuas_observadas 
                SET estado = %s, fecha_correccion = NULL
                WHERE id = %s;
                """,
                (nuevo_estado, fua_id)
            )

        # 3. Registrar en el historial guardando el DNI del usuario que hace el cambio actual
        cur.execute(
            """
            INSERT INTO fua_historial (fua_id, numero_fua, accion, estado_anterior, estado_nuevo, usuario_dni)
            VALUES (%s, %s, %s, %s, %s, %s);
            """,
            (fua_id, numero_fua, f"Cambio a {nuevo_estado}", estado_anterior, nuevo_estado, dni_usuario)
        )

        conn.commit()
        return True, "¡Estado actualizado y registrado en el historial correctamente!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al actualizar: {e}"
    finally:
        cur.close()
        conn.close()

def registrar_establecimiento(codigo_renaes, nombre_establecimiento):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO establecimientos (codigo_renaes, nombre_establecimiento, activo)
            VALUES (%s, %s, TRUE);
            """,
            (codigo_renaes.strip(), nombre_establecimiento.strip())
        )
        conn.commit()
        return True, "¡Establecimiento registrado con éxito!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al registrar establecimiento: {e}"
    finally:
        cur.close()
        conn.close()

def obtener_todos_establecimientos():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, codigo_renaes, nombre_establecimiento, activo FROM establecimientos ORDER BY nombre_establecimiento ASC;")
        return cur.fetchall()
    except Exception:
        return []
    finally:
        cur.close()
        conn.close()

def actualizar_establecimiento(id_est, codigo_renaes, nombre_establecimiento, activo):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE establecimientos 
            SET codigo_renaes = %s, nombre_establecimiento = %s, activo = %s
            WHERE id = %s;
            """,
            (codigo_renaes.strip(), nombre_establecimiento.strip(), activo, id_est)
        )
        conn.commit()
        return True, "¡Establecimiento actualizado correctamente!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al actualizar establecimiento: {e}"
    finally:
        cur.close()
        conn.close()

def registrar_profesional(dni, nombres_apellidos, profesion_o_especialidad, establecimiento_id):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO profesionales (dni, nombres_apellidos, profesion_o_especialidad, establecimiento, activo)
            VALUES (%s, %s, %s, %s, TRUE);
            """,
            (dni.strip(), nombres_apellidos.strip(), profesion_o_especialidad.strip(), establecimiento_id)
        )
        conn.commit()
        return True, "¡Profesional registrado con éxito!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al registrar profesional: {e}"
    finally:
        cur.close()
        conn.close()

def obtener_todos_profesionales():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT p.dni, p.nombres_apellidos, p.profesion_o_especialidad, e.nombre_establecimiento, p.activo, p.establecimiento
            FROM profesionales p
            LEFT JOIN establecimientos e ON p.establecimiento = e.id
            ORDER BY p.nombres_apellidos ASC;
            """
        )
        return cur.fetchall()
    except Exception:
        return []
    finally:
        cur.close()
        conn.close()

def actualizar_profesional(dni, nombres_apellidos, profesion_o_especialidad, establecimiento_id, activo):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE profesionales 
            SET nombres_apellidos = %s, profesion_o_especialidad = %s, establecimiento = %s, activo = %s
            WHERE dni = %s;
            """,
            (nombres_apellidos.strip(), profesion_o_especialidad.strip(), establecimiento_id, activo, dni.strip())
        )
        conn.commit()
        return True, "¡Profesional actualizado correctamente!"
    except Exception as e:
        conn.rollback()
        return False, f"Error al actualizar profesional: {e}"
    finally:
        cur.close()
        conn.close()

def obtener_estadisticas_generales():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN estado = 'Pendiente' THEN 1 ELSE 0 END) AS total_pendientes,
                SUM(CASE WHEN estado = 'Corregido' THEN 1 ELSE 0 END) AS total_corregidos
            FROM fuas_observadas;
            """
        )
        return cur.fetchone()
    except Exception:
        return (0, 0, 0)
    finally:
        cur.close()
        conn.close()

def obtener_reporte_por_establecimiento():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 
                COALESCE(e.nombre_establecimiento, 'Sin Establecimiento') AS establecimiento,
                SUM(CASE WHEN f.estado = 'Pendiente' THEN 1 ELSE 0 END) AS pendientes,
                SUM(CASE WHEN f.estado = 'Corregido' THEN 1 ELSE 0 END) AS corregidos,
                COUNT(*) AS total
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            GROUP BY e.nombre_establecimiento
            ORDER BY total DESC;
            """
        )
        return cur.fetchall()
    except Exception:
        return []
    finally:
        cur.close()
        conn.close()

def obtener_reporte_por_profesional():
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 
                COALESCE(NULLIF(p.nombres_apellidos, ''), NULLIF(CONCAT('DNI: ', f.profesional_dni), 'DNI: '), 'Sin Profesional Asignado') AS profesional,
                COALESCE(NULLIF(p.profesion_o_especialidad, ''), 'N/A') AS especialidad,
                COALESCE(NULLIF(e.nombre_establecimiento, ''), 'Sin Establecimiento') AS establecimiento,
                SUM(CASE WHEN f.estado = 'Pendiente' THEN 1 ELSE 0 END) AS pendientes,
                SUM(CASE WHEN f.estado = 'Corregido' THEN 1 ELSE 0 END) AS corregidos,
                COUNT(*) AS total
            FROM fuas_observadas f
            LEFT JOIN profesionales p ON TRIM(f.profesional_dni) = TRIM(p.dni)
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            GROUP BY f.profesional_dni, p.nombres_apellidos, p.profesion_o_especialidad, e.nombre_establecimiento
            ORDER BY total DESC;
            """
        )
        resultados = cur.fetchall()
        return resultados
    except Exception as e:
        print("ERROR SQL PROFESIONALES:", e)
        return []
    finally:
        cur.close()
        conn.close()

def obtener_reporte_filtrado(fecha_inicio, fecha_fin, establecimientos_sel, profesionales_sel):
    conn = init_connection()
    cur = conn.cursor()
    try:
        query = """
            SELECT 
                f.numero_fua,  -- <--- Aquí debe estar numero_fua
                f.fecha_registro,
                COALESCE(NULLIF(p.nombres_apellidos, ''), NULLIF(CONCAT('DNI: ', f.profesional_dni), 'DNI: '), 'Sin Profesional Asignado') AS profesional,
                COALESCE(NULLIF(p.profesion_o_especialidad, ''), 'N/A') AS especialidad,
                COALESCE(e.nombre_establecimiento, 'Sin Establecimiento') AS establecimiento,
                f.estado
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            LEFT JOIN profesionales p ON TRIM(f.profesional_dni::text) = TRIM(p.dni::text)
            WHERE f.fecha_registro::date >= %s AND f.fecha_registro::date <= %s
        """
        params = [fecha_inicio, fecha_fin]

        if establecimientos_sel:
            query += " AND e.nombre_establecimiento = ANY(%s)"
            params.append(establecimientos_sel)

        if profesionales_sel:
            query += " AND COALESCE(NULLIF(p.nombres_apellidos, ''), NULLIF(CONCAT('DNI: ', f.profesional_dni), 'DNI: '), 'Sin Profesional Asignado') = ANY(%s)"
            params.append(profesionales_sel)

        query += " ORDER BY f.fecha_registro DESC;"

        cur.execute(query, params)
        return cur.fetchall()
    except Exception as e:
        st.error(f"Error detallado en la consulta SQL: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def obtener_reporte_completo_filtrado(fecha_inicio, fecha_fin, establecimientos_sel, profesionales_sel):
    conn = init_connection()
    cur = conn.cursor()
    try:
        query = """
            SELECT 
                f.id AS fua_id,
                f.numero_fua,
                COALESCE(e.nombre_establecimiento, 'Sin Establecimiento') AS establecimiento,
                f.afiliado_dni,
                f.afiliado_nombre,
                f.afiliado_appaterno,
                f.afiliado_apmaterno,
                f.afiliado_fecha_nacimiento,
                f.profesional_dni,
                COALESCE(p.nombres_apellidos, 'Sin Profesional Asignado') AS profesional_nombre,
                COALESCE(p.profesion_o_especialidad, 'N/A') AS profesional_especialidad,
                f.digitador_dni,
                f.tipo_observacion,
                f.detalle_observacion,
                f.fecha_atencion_fua,
                f.estado,
                f.fecha_registro,
                f.fecha_correccion
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            LEFT JOIN profesionales p ON TRIM(f.profesional_dni::text) = TRIM(p.dni::text)
            WHERE f.fecha_registro::date >= %s AND f.fecha_registro::date <= %s
        """
        params = [fecha_inicio, fecha_fin]

        if establecimientos_sel:
            query += " AND e.nombre_establecimiento = ANY(%s)"
            params.append(establecimientos_sel)

        if profesionales_sel:
            query += " AND COALESCE(NULLIF(p.nombres_apellidos, ''), NULLIF(CONCAT('DNI: ', f.profesional_dni), 'DNI: '), 'Sin Profesional Asignado') = ANY(%s)"
            params.append(profesionales_sel)

        query += " ORDER BY f.fecha_registro DESC;"

        cur.execute(query, params)
        return cur.fetchall()
    except Exception as e:
        st.error(f"Error detallado en la consulta SQL completa: {e}")
        return []
    finally:
        cur.close()
        conn.close()

def generar_excel_reportes():
    conn = init_connection()
    cur = conn.cursor()
    try:
        # Consulta SQL limpia SIN incluir f.id
        query = """
            SELECT 
                f.numero_fua,
                COALESCE(e.nombre_establecimiento, 'Sin Establecimiento') AS establecimiento,
                f.afiliado_dni,
                f.afiliado_nombre,
                f.afiliado_appaterno,
                f.afiliado_apmaterno,
                f.afiliado_fecha_nacimiento,
                f.profesional_dni,
                COALESCE(p.nombres_apellidos, 'Sin Profesional Asignado') AS profesional_nombre,
                COALESCE(p.profesion_o_especialidad, 'N/A') AS profesional_especialidad,
                f.digitador_dni,
                f.tipo_observacion,
                f.detalle_observacion,
                f.fecha_atencion_fua,
                f.estado,
                f.fecha_registro,
                f.fecha_correccion
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
            LEFT JOIN profesionales p ON TRIM(f.profesional_dni::text) = TRIM(p.dni::text)
            ORDER BY f.fecha_registro DESC;
        """
        cur.execute(query)
        datos = cur.fetchall()
        
        # DataFrame con las columnas exactas (sin rastro de ID Interno)
        df = pd.DataFrame(
            datos, 
            columns=[
                "Nro FUA", "Establecimiento", "Afiliado DNI", 
                "Afiliado Nombres", "Afiliado Ap. Paterno", "Afiliado Ap. Materno", 
                "Afiliado F. Nacimiento", "Profesional DNI", "Profesional Nombre", 
                "Profesional Especialidad", "Digitador DNI", "Tipo de Observación", 
                "Detalle Observación", "Fecha Atención FUA", "Estado", 
                "Fecha Registro", "Fecha Corrección"
            ]
        )
        
        import io
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Reportes_Generales')
        return output.getvalue()
    except Exception as e:
        print(f"Error generando Excel general: {e}")
        return b""
    finally:
        cur.close()
        conn.close()

def obtener_todos_profesionales():
    # Ejemplo de cómo debe estructurarse tu función backend para la base de datos:
    query = """
        SELECT 
            p.dni,
            p.nombres_apellidos,
            p.profesion_o_especialidad,
            e.nombre_establecimiento,
            p.activo,
            p.establecimiento AS establecimiento_id
        FROM profesionales p
        LEFT JOIN establecimientos e ON p.establecimiento::integer = e.id
        ORDER BY p.nombres_apellidos ASC;
    """
    # Ejecutas la query y devuelves los registros como lista de tuplas/diccionarios

def render_dashboard(estilos):  # Ya no necesita recibir 'conn' como parámetro, lo crea adentro

    CARD_BG = estilos["bg_card"]
    CARD_BORDER = estilos["border_card"]
    TEXT_MAIN = estilos["text_main"]
    TEXT_SUB = estilos["text_sub"]

    ACCENT = estilos.get("accent", "#2f81f7")

    st.title("📊 Estadisticas de FUAs Observadas")
    st.markdown(
        "Resumen y métricas en tiempo real de las observaciones registradas en los establecimientos de salud."
    )

    # 1. Obtener conexión usando tu función existente
    try:
        conn = init_connection()
    except Exception as e:
        st.error(f"Error al conectar con la base de datos: {e}")
        return

    # 2. Cargar datos directamente desde la tabla 'fuas_observadas'
    try:
        query_fuas = """
            SELECT 
                f.id,
                f.numero_fua,
                e.nombre_establecimiento AS establecimiento,
                f.afiliado_dni,
                f.tipo_observacion,
                f.fecha_atencion_fua,
                f.estado,
                f.fecha_registro
            FROM fuas_observadas f
            LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
        """
        df_fuas = pd.read_sql(query_fuas, conn)
    except Exception as e:
        st.error(f"Error al consultar los datos de las FUAs: {e}")
        conn.close()
        return
    finally:
        conn.close()  # Cerramos la conexión para liberar recursos

    if df_fuas.empty:
        st.info(
            "No hay registros de FUAs observadas en la base de datos todavía."
        )
        return

    # ---------------------------------------------------------
    # 3. FILTRO LATERAL OPCIONAL POR ESTABLECIMIENTO
    # ---------------------------------------------------------
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔍 Filtros del Dashboard")

    lista_estab = ["Todos"] + sorted(
        df_fuas["establecimiento"].dropna().unique().tolist()
    )
    estab_seleccionado = st.sidebar.selectbox(
        "Filtrar por Establecimiento", lista_estab
    )

    if estab_seleccionado != "Todos":
        df_fuas = df_fuas[df_fuas["establecimiento"] == estab_seleccionado]

    # ---------------------------------------------------------
    # 4. TARJETAS DE MÉTRICAS (KPIs)
    # ---------------------------------------------------------
    total_observados = len(df_fuas)
    pendientes = len(
        df_fuas[df_fuas["estado"].astype(str).str.lower() == "pendiente"]
    )
    corregidos = len(
        df_fuas[df_fuas["estado"].astype(str).str.lower() == "corregido"]
    )
    anuladas = len(
        df_fuas[df_fuas["estado"].astype(str).str.lower() == "anulado"]
    )
    num_establecimientos = df_fuas["establecimiento"].nunique()

    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(f"""
            <div style="background-color: {CARD_BG}; padding: 12px; border-radius: 8px; border: 1px solid {CARD_BORDER}; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                <div>
                    <p style="color: {TEXT_SUB}; font-size: 12px; margin-bottom: 2px;">Total FUAs Observadas</p>
                    <h2 style="color: {TEXT_MAIN}; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{total_observados:,}</h2>
                </div>
                <div>
                    <span style="background-color: #1a2332; color: #4fa3ff; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                        Total
                    </span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div style="background-color: {CARD_BG}; padding: 12px; border-radius: 8px; border: 1px solid {CARD_BORDER}; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                <div>
                    <p style="color: {TEXT_SUB}; font-size: 12px; margin-bottom: 2px;">Pendientes</p>
                    <h2 style="color: {TEXT_MAIN}; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{pendientes:,}</h2>
                </div>
                <div>
                    <span style="background-color: #332b00; color: #ffcc00; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                        Requieren atención
                    </span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
            <div style="background-color: {CARD_BG}; padding: 12px; border-radius: 8px; border: 1px solid {CARD_BORDER}; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                <div>
                    <p style="color: {TEXT_SUB}; font-size: 12px; margin-bottom: 2px;">Corregidas</p>
                    <h2 style="color: {TEXT_MAIN}; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{corregidos:,}</h2>
                </div>
                <div>
                    <span style="background-color: #113322; color: #00cc66; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                        Completadas
                    </span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
            <div style="background-color: {CARD_BG}; padding: 12px; border-radius: 8px; border: 1px solid {CARD_BORDER}; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                <div>
                    <p style="color: {TEXT_SUB}; font-size: 12px; margin-bottom: 2px;">Anuladas</p>
                    <h2 style="color: {TEXT_MAIN}; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{anuladas:,}</h2>
                </div>
                <div>
                    <span style="background-color: #331111; color: #ff4444; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                        Anuladas
                    </span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
            <div style="background-color: {CARD_BG}; padding: 12px; border-radius: 8px; border: 1px solid {CARD_BORDER}; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                <div>
                    <p style="color: {TEXT_SUB}; font-size: 12px; margin-bottom: 2px;">Establecimientos</p>
                    <h2 style="color: {TEXT_MAIN}; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{num_establecimientos} / 6</h2>
                </div>
                <div>
                    <span style="background-color: #1a2332; color: #4fa3ff; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                        Activos
                    </span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # ---------------------------------------------------------
    # 5. GRÁFICOS INTERACTIVOS (PLOTLY)
    # ---------------------------------------------------------
    # Definimos la plantilla y colores según el tema seleccionado
    if "Claro" in tema_seleccionado:
        plotly_template = "plotly_white"
        bg_grafico = "#FFFFFF"
        color_texto = "#111827"

    elif "MINSA" in tema_seleccionado:

        plotly_template = "plotly_dark"

        bg_grafico = estilos["chart_bg"]
        color_texto = estilos["chart_text"]

    else:

        plotly_template = (
        "plotly_white"
        if "Claro" in tema_seleccionado
        else "plotly_dark"
    )

    bg_grafico = estilos["chart_bg"]
    color_texto = estilos["chart_text"]

    col_g1, col_g2 = st.columns(2)

    # ===============================
    # GRÁFICO DE BARRAS
    # ===============================

    with col_g1:

        st.subheader("🏥 Observaciones por Establecimiento")

        df_estab_counts = (
            df_fuas["establecimiento"]
            .value_counts()
            .reset_index()
        )

        df_estab_counts.columns = [
            "Establecimiento",
            "Total"
        ]

        fig_bar = px.bar(
            df_estab_counts,
            x="Establecimiento",
            y="Total",
            color="Establecimiento",
            text="Total",
            title="Cantidad de FUAs por IPRESS"
        )

        fig_bar.update_traces(
            textposition="outside"
        )

        fig_bar.update_layout(
            template=plotly_template,

            paper_bgcolor=bg_grafico,
            plot_bgcolor=bg_grafico,

            showlegend=False,

            font=dict(
                color=color_texto,
                size=12
            ),

            title_font=dict(
                color=color_texto,
                size=20
            ),

            xaxis_title="",
            yaxis_title="FUAs",

            margin=dict(
                l=20,
                r=20,
                t=60,
                b=40
            )
        )

        fig_bar.update_xaxes(
            tickfont=dict(
                color=color_texto,
                size=11
            )
        )

        fig_bar.update_yaxes(
            tickfont=dict(
                color=color_texto,
                size=11
            ),
            title_font=dict(
                color=color_texto,
                size=14
            ),
            showgrid=True,
            gridcolor="#D1D5DB" if "Claro" in tema_seleccionado else "#30363D"
        )

        st.plotly_chart(
            fig_bar,
            use_container_width=True
        )

    # ===============================
    # GRÁFICO CIRCULAR
    # ===============================

    with col_g2:

        st.subheader("📌 Estado de las Observaciones")

        df_estado_counts = (
            df_fuas["estado"]
            .value_counts()
            .reset_index()
        )

        df_estado_counts.columns = [
            "Estado",
            "Cantidad"
        ]

        fig_pie = px.pie(
            df_estado_counts,
            names="Estado",
            values="Cantidad",
            hole=0.40,
            title="Proporción por Estado",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )

        fig_pie.update_traces(
            textfont=dict(
                color=color_texto,
                size=12
            )
        )

        fig_pie.update_layout(
            template=plotly_template,

            paper_bgcolor=bg_grafico,
            plot_bgcolor=bg_grafico,

            font=dict(
                color=color_texto,
                size=12
            ),

            title_font=dict(
                color=color_texto,
                size=20
            ),

            legend=dict(
                font=dict(
                    color=color_texto,
                    size=12
                )
            ),

            margin=dict(
                l=20,
                r=20,
                t=60,
                b=20
            )
        )

        st.plotly_chart(
            fig_pie,
            use_container_width=True
        )

def buscar_fua_por_numero(numero_fua):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 
                f.id,
                f.numero_fua,
                f.establecimiento_id,
                f.afiliado_dni,
                f.afiliado_nombre,
                f.afiliado_appaterno,
                f.afiliado_apmaterno,
                f.afiliado_fecha_nacimiento,
                f.profesional_dni,
                f.tipo_observacion,
                f.detalle_observacion,
                f.fecha_atencion_fua,
                f.estado,
                f.id_prestacion,
                f.nombre_prestacion
            FROM fuas_observadas f
            WHERE TRIM(f.numero_fua) = TRIM(%s)
            LIMIT 1;
            """,
            (numero_fua,)
        )
        row = cur.fetchone()
        if row:
            return {
                "id": row[0],
                "numero_fua": row[1],
                "establecimiento_id": row[2],
                "afiliado_dni": row[3],
                "afiliado_nombre": row[4],
                "afiliado_appaterno": row[5],
                "afiliado_apmaterno": row[6],
                "afiliado_fecha_nacimiento": row[7],
                "profesional_dni": row[8],
                "tipo_observacion": row[9],
                "detalle_observacion": row[10],
                "fecha_atencion_fua": row[11],
                "estado": row[12],
                "id_prestacion": row[13],
                "nombre_prestacion": row[14]
            }
        return None
    except Exception as e:
        print("ERROR AL BUSCAR FUA POR NÚMERO:", e)
        return None
    finally:
        cur.close()
        conn.close()

def actualizar_fua_observada(datos):
    conn = init_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE fuas_observadas
            SET 
                numero_fua = %s,
                id_prestacion = %s,
                nombre_prestacion = %s,
                establecimiento_id = %s,
                afiliado_dni = %s,
                afiliado_nombre = %s,
                afiliado_appaterno = %s,
                afiliado_apmaterno = %s,
                afiliado_fecha_nacimiento = %s,
                profesional_dni = %s,
                tipo_observacion = %s,
                detalle_observacion = %s,
                fecha_atencion_fua = %s
            WHERE id = %s;
            """,
            (
                datos["numero_fua"],
                datos["id_prestacion"],
                datos["nombre_prestacion"],
                datos["establecimiento_id"],
                datos["afiliado_dni"],
                datos["afiliado_nombre"],
                datos["afiliado_appaterno"],
                datos["afiliado_apmaterno"],
                datos["afiliado_fecha_nacimiento"],
                datos["profesional_dni"],
                datos["tipo_observacion"],
                datos["detalle_observacion"],
                datos["fecha_atencion_fua"],
                datos["id"]
            )
        )
        conn.commit()
        return True, "FUA actualizada correctamente."
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cur.close()
        conn.close()

def buscar_descripcion_prestacion(codigo):
    if not codigo or not str(codigo).strip():
        return ""
    
    conn = init_connection()
    cur = conn.cursor()
    try:
        # Consulta coincidiendo exactamente con las columnas de tu tabla en PostgreSQL
        cur.execute(
            "SELECT nombre_prestacion FROM prestaciones WHERE id_prestacion = %s;", 
            (str(codigo).strip(),)
        )
        resultado = cur.fetchone()
        return resultado[0] if resultado else ""
    except Exception as e:
        print("Error al buscar prestación:", e)
        return ""
    finally:
        cur.close()
        conn.close()

def actualizar_descripcion_automatica():
    # 1. Obtiene el código ingresado por el usuario en el widget
    codigo = st.session_state.get("input_id_prestacion", "")
    
    # 2. Busca en la base de datos y actualiza el session_state de la descripción
    if codigo:
        desc = buscar_descripcion_prestacion(codigo)
        st.session_state["input_nombre_prestacion"] = desc
    else:
        st.session_state["input_nombre_prestacion"] = ""

def cargar_excel_arfsis_db(df):
  """Recibe un DataFrame de Pandas y lo inserta masivamente en 'digitados_arfsis'."""
  # Reemplazar NaNs por None (NULL en PostgreSQL)
  df = df.where(pd.notna(df), None)

  # Conexión a tu BD
  conn = psycopg2.connect(
      host="localhost",
      database="tu_base_datos",  # <-- pon tu BD real
      user="postgres",  # <-- pon tu usuario real
      password="tu_password",  # <-- pon tu clave real
      port="5432",
  )
  cursor = conn.cursor()

  try:
    # 1. Vaciar la tabla antes de cargar la lista actualizada
    cursor.execute("TRUNCATE TABLE digitados_arfsis RESTART IDENTITY;")

    insert_query = """
            INSERT INTO digitados_arfsis (
                numero_fua, establecimiento, numero_dni, ap_paterno, ap_materno,
                primer_nombre, otros_nombres, fecha_nac, id_servicio, digitador, fecha_registro
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (numero_fua) DO UPDATE SET
                digitador = EXCLUDED.digitador,
                fecha_registro = EXCLUDED.fecha_registro;
        """

    datos_para_insertar = []
    for _, row in df.iterrows():
      # Formatear fechas correctamente si vienen como texto o Timestamp
      f_nac = (
          pd.to_datetime(row.get("fecha_nacimiento"), dayfirst=True, errors="coerce")
          if row.get("fecha_nacimiento")
          else None
      )
      f_reg = (
          pd.to_datetime(row.get("fecha_registro"), dayfirst=True, errors="coerce")
          if row.get("fecha_registro")
          else None
      )

      datos_para_insertar.append((
          (
              str(row.get("numero_fua", "")).strip()
              if row.get("numero_fua")
              else None
          ),
          row.get("establecimiento"),
          (
              str(row.get("numero_dni", "")).strip()
              if row.get("numero_dni")
              else None
          ),
          row.get("ap_paterno"),
          row.get("ap_materno"),
          row.get("primer_nombre"),
          row.get("otros_nombres"),
          f_nac.date() if pd.notna(f_nac) else None,
          str(row.get("ID Servicio", "")),
          row.get("digitador"),
          f_reg.date() if pd.notna(f_reg) else None,
      ))

    cursor.executemany(insert_query, datos_para_insertar)
    conn.commit()
    return True, f"Se cargaron exitosamente {len(datos_para_insertar)} registros."

  except Exception as e:
    conn.rollback()
    return False, f"Error en la base de datos: {e}"
  finally:
    cursor.close()
    conn.close()

def obtener_fuar_guardados(engine):
  # Consulta los registros de la tabla en PostgreSQL
  query = "SELECT * FROM digitados_arfsis ORDER BY 1 DESC"
  return pd.read_sql(query, con=engine)

def registrar_cargo_entrega(df_bloque_fuas, profesional, dni_prof, establecimiento, usuario_actual):
    conn = init_connection()
    cur = conn.cursor()
    try:
        # 1. Generar un código único correlativo
        fecha_corta = datetime.now().strftime('%d%m%y')
        aleatorio = random.randint(1000, 9999)
        codigo_cargo = f"CARGO-{fecha_corta}-{aleatorio}"
        
        # 2. Insertar el encabezado del Cargo (Guarda el nombre del usuario actual)
        query_cargo = """
            INSERT INTO cargos_entrega (codigo_cargo, profesional_responsable, dni_profesional, establecimiento, total_fuas, usuario_registro)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
        """
        cur.execute(query_cargo, (codigo_cargo, profesional, dni_prof, establecimiento, len(df_bloque_fuas), usuario_actual))
        cargo_id = cur.fetchone()[0]
        
        # 3. Vincular los IDs de este bloque al nuevo cargo
        ids_fuas = [int(x) for x in df_bloque_fuas["ID"].tolist()]
        query_update_fuas = """
            UPDATE fuas_observadas
            SET cargo_id = %s
            WHERE id = ANY(%s);
        """
        cur.execute(query_update_fuas, (cargo_id, ids_fuas))
        
        # 4. Registrar movimiento en fua_historial para cada FUA del bloque
        for fua_id in ids_fuas:
            query_hist = """
                INSERT INTO fua_historial (fua_id, accion, estado_anterior, estado_nuevo, usuario_dni)
                VALUES (%s, %s, %s, %s, %s);
            """
            # Mantenemos 'Pendiente' o el estado actual que tenía la FUA según tu lógica
            cur.execute(query_hist, (fua_id, f"Entregado en {codigo_cargo}", "Pendiente", "Entregado a Profesional", usuario_actual))
            
        conn.commit()
        return cargo_id, codigo_cargo
    except Exception as e:
        conn.rollback()
        st.error(f"Error al registrar el cargo: {e}")
        return None, None
    finally:
        cur.close()
        conn.close()

def generar_html_cargo(codigo_cargo, profesional_recibe, establecimiento, df_bloque, usuario_actual):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            /* 📄 Fondo blanco y texto oscuro fijo para que no dependa del modo oscuro */
            body {{ 
                font-family: Arial, sans-serif; 
                margin: 0; 
                padding: 20px; 
                background-color: #ffffff; 
                color: #000000; 
            }}
            .header {{ text-align: center; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #ffffff; }}
            th, td {{ border: 1px solid black; padding: 6px; font-size: 12px; text-align: left; color: #000000; }}
            th {{ background-color: #f2f2f2; text-align: center; color: #000000; }}
            
            /* 🖨️ ESTILOS PARA OCULTAR EL BOTÓN AL MOMENTO DE IMPRIMIR */
            @media print {{
                .no-print {{ display: none; }}
            }}
        </style>
    </head>
    <body>
    
        <!-- 🖨️ BOTÓN DE IMPRESIÓN RÁPIDA -->
        <div class="no-print" style="text-align: right; margin-bottom: 15px;">
            <button onclick="window.print()" style="background-color: #2e7d32; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold;">
                🖨️ Imprimir Cargo
            </button>
        </div>

        <!-- 📄 CONTENIDO DEL CARGO -->
        <div class="header">
            <h3>CARGO DE ENTREGA DE FUAS OBSERVADAS</h3>
            <p>Nº: {codigo_cargo}</p>
        </div>
        
        <p><b>Establecimiento:</b> {establecimiento}</p>
        <p><b>Profesional Responsable / Recibe:</b> {profesional_recibe}</p>
        <p><b>Fecha de Emisión:</b> {pd.Timestamp.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        <p><b>Total de FUAs Observadas:</b> {len(df_bloque)}</p>

        <table>
            <thead>
                <tr>
                    <th>Nº</th>
                    <th>Nº FUA</th>
                    <th>Profesional</th>
                    <th>Observación</th>
                    <th>F. Atención</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Rellenamos las filas usando iterrows para capturar con precisión los datos
    for idx, (index, row) in enumerate(df_bloque.iterrows(), 1):
        html += f"""
                <tr>
                    <td style="text-align: center;">{idx}</td>
                    <td>{row.get('Nº FUA', '-')}</td>
                    <td>{row.get('Profesional', '-')}</td>
                    <td>{row.get('Tipo Observación', '-')}</td>
                    <td>{row.get('Fecha Atención', '-')}</td>
                </tr>
        """
        
    html += f"""
            </tbody>
        </table>

        <div style="display: flex; justify-content: space-between; margin-top: 100px;">
            <div style="width: 40%; text-align: center;">
                <div style="border-top: 1px solid black; padding-top: 5px;">
                    <b>Entregado Por:</b> {usuario_actual}<br>
                    <span style="font-size: 11px;">Data Entry / Digitación</span>
                </div>
            </div>
            <div style="width: 40%; text-align: center;">
                <div style="border-top: 1px solid black; padding-top: 5px;">
                    <b>Recibido Conforme:</b> {profesional_recibe}<br>
                    <span style="font-size: 11px;">Firma y Sello del Profesional</span>
                </div>
            </div>
        </div>

    </body>
    </html>
    """
    return html

def restaurar_backup_bd(archivo_sql_path):
    """
    Restaura un archivo .sql detectando automáticamente si es entorno local o remoto (Supabase).
    """
    try:
        # Obtenemos los parámetros de conexión actuales desde st.secrets
        db_host = st.secrets["postgres"]["host"]
        db_port = str(st.secrets["postgres"]["port"])
        db_name = st.secrets["postgres"]["database"]
        db_user = st.secrets["postgres"]["user"]
        db_password = st.secrets["postgres"]["password"]
    except Exception as e:
        st.error(f"❌ Faltan credenciales en st.secrets para la base de datos: {e}")
        return False
    
    # Detectamos si es Supabase o entorno local basado en el host
    es_nube = "supabase" in db_host or "pooler" in db_host
    
    if es_nube:
        st.info("☁️ Conectando con la nube de Supabase para restauración...")
    else:
        st.info("💻 Conectando con la base de datos local...")
    
    # Comando psql estándar (compatible con local y Supabase)
    # Nota: Si estás en Windows y 'psql' no es reconocido directamente, 
    # puedes cambiar "psql" por la ruta completa, ej: r"C:\Program Files\PostgreSQL\18\bin\psql.exe"
    comando = [
        "psql",
        f"--host={db_host}",
        f"--port={db_port}",
        f"--dbname={db_name}",
        f"--username={db_user}",
        f"--file={archivo_sql_path}"
    ]
    
    # Configuramos la contraseña de forma segura por variable de entorno
    env = os.environ.copy()
    env["PGPASSWORD"] = db_password
    
    try:
        resultado = subprocess.run(
            comando, 
            capture_output=True, 
            text=True, 
            env=env, 
            check=True
        )
        st.success("✅ ¡Base de datos restaurada exitosamente!")
        return True
    except subprocess.CalledProcessError as e:
        st.error(f"❌ Error al restaurar la base de datos:")
        st.code(e.stderr)
        return False
    except FileNotFoundError:
        st.error("❌ No se encontró el comando 'psql' en el sistema. Asegúrate de que PostgreSQL esté instalado y en las variables de entorno (PATH).")
        return False

def generar_backup_bd():
    """
    Genera un respaldo usando la ruta de pg_dump especificada desde la interfaz.
    """
    try:
        db_host = st.secrets["postgres"]["host"]
        db_port = str(st.secrets["postgres"]["port"])
        db_name = st.secrets["postgres"]["database"]
        db_user = st.secrets["postgres"]["user"]
        db_password = st.secrets["postgres"]["password"]
    except Exception as e:
        st.error(f"Faltan credenciales en st.secrets: {e}")
        return None
    
    # Campo en la interfaz para ajustar la ruta si estás en local
    pg_dump_path = st.text_input(
        "Ruta del ejecutable pg_dump.exe (Solo para entorno local):",
        value=r"C:\Program Files\PostgreSQL\18\bin\pg_dump.exe"
    )
    
    # Si estamos en la nube de Streamlit Cloud, detectamos automáticamente si existe el binario del paquete Linux
    es_nube = "supabase" in db_host or "pooler" in db_host or not os.path.exists("C:")
    if es_nube:
        pg_dump_path = "pg_dump" # En Linux de la nube se usa directamente gracias al packages.txt
    elif not os.path.exists(pg_dump_path):
        st.error(f"No se encontró el archivo en la ruta: {pg_dump_path}. Verifica la carpeta de tu instalación de PostgreSQL.")
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"backup_fuas_{timestamp}.sql"
    
    temp_dir = tempfile.gettempdir()
    archivo_destino = os.path.join(temp_dir, nombre_archivo)
    
    comando = [
        pg_dump_path,
        f"--host={db_host}",
        f"--port={db_port}",
        f"--dbname={db_name}",
        f"--username={db_user}",
        "--no-owner",
        "--no-privileges",
        f"--file={archivo_destino}"
    ]
    
    env = os.environ.copy()
    env["PGPASSWORD"] = db_password
    
    try:
        with st.spinner("Generando respaldo de la base de datos..."):
            subprocess.run(
                comando, 
                env=env, 
                check=True, 
                capture_output=True, 
                text=True
            )
        return archivo_destino
    except subprocess.CalledProcessError as e:
        st.error("Error al generar el respaldo:")
        st.code(e.stderr)
        return None
    
# ==========================================
# 2. CONTROL DE SESIÓN Y NAVEGACIÓN
# 2. CONTROL DE SESIÓN Y NAVEGACIÓN
# =========================================================
if "user" not in st.session_state:
    st.session_state["user"] = None

if "mostrar_login" not in st.session_state:
    st.session_state["mostrar_login"] = False

if "menu_activo" not in st.session_state:
    st.session_state["menu_activo"] = "Dashboard"


# =========================================================
# 3. INTERFAZ GRÁFICA (UI) - BARRA SUPERIOR
# =========================================================
col_titulo, col_btn = st.columns([8, 2])

if not st.session_state["mostrar_login"] and st.session_state["user"] is None:
    col_titulo, col_btn = st.columns([8, 2])
    with col_titulo:
        st.title("📊 Panel Estadístico y Ranking de FUAs")
        st.markdown("Visualización general y seguimiento de observaciones en los establecimientos de salud.")
    with col_btn:
        st.write("") 
        if st.button("🔑 Iniciar Sesión", use_container_width=True, key="btn_abrir_login"):
            st.session_state["mostrar_login"] = True
            st.rerun()
    st.markdown("---")


# =========================================================
# 4. GESTIÓN DE VISTAS (LOGIN, PÚBLICA, PRIVADA)
# =========================================================

# --- CASO 1: USUARIO NO AUTENTICADO ---
if st.session_state["user"] is None:
    
    # CSS PARA LA TARJETA CON DEGRADADO MAESTRO
    st.markdown("""
        <style>
        h1 {
            color: #0f172a !important;
            font-weight: 700 !important;
        }
        .stApp {
            background-color: #f1f5f9 !important;
        }

        /* Quitar bordes y fondos por defecto del formulario */
        [data-testid="stForm"] {
            background: transparent !important;
            border: none !important;
            padding: 0px 10px !important;
            box-shadow: none !important;
        }

        /* Botón de ingreso estilizado */
        .stButton > button,
        .stFormSubmitButton > button {
            background: linear-gradient(135deg, #1d367d, #1d4ed8) !important;
            color: white !important;
            border: 1px solid rgba(255, 255, 255, 0.3) !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            transition: .2s ease all !important;
        }

        .stButton > button:hover,
        .stFormSubmitButton > button:hover {
            background: linear-gradient(135deg, #1e3a8a, #2563eb) !important;
            transform: translateY(-2px);
            box-shadow: 0 4px 10px rgba(37,99,235,.3);
        }

        .stButton > button p,
        .stFormSubmitButton > button p {
            color: white !important;
        }
        /* Fondo con degradado para todo el formulario */
        div[data-testid="stForm"] {
            background: linear-gradient(135deg, #1e3a8a, #2563eb) !important;
            border: none !important;
            border-radius: 0px !important;
            padding: 15px 20px !important;
            box-shadow: none !important;
        }

        /* Etiquetas del formulario (Usuario y Contraseña) en blanco */
        div[data-testid="stForm"] label p {
            color: #ffffff !important;
            font-weight: 600 !important;
        }
        
        /* Cajas de texto blancas con letras oscuras */
        div[data-baseweb="input"] > div {
            background: #ffffff !important;
            border: 1px solid #cbd5e1 !important;
            border-radius: 8px !important;
            box-shadow: none !important;
        }

        div[data-baseweb="input"] > div:hover {
            border: 1px solid #94a3b8 !important;
        }

        div[data-baseweb="input"] > div:focus-within {
            border: 1px solid #2563eb !important;
            box-shadow: 0 0 0 3px rgba(37,99,235,.15) !important;
        }

        input {
            color: #0f172a !important;
            background: white !important;
        }

        input::placeholder {
            color: #94a3b8 !important;
        }

        /* ==========================
        CORRECCIÓN DE TEXTOS EN VISTA PÚBLICA
        ========================== */
        .stMarkdown h3, .stMarkdown p, .stAlert p {
            color: #0f172a !important;
        }
        /* Forzar color oscuro y nítido para los números y etiquetas de st.metric */
        [data-testid="stMetricValue"] {
            color: #0f172a !important;
            font-weight: 700 !important;
        }
        
        [data-testid="stMetricLabel"] {
            color: #475569 !important;
            font-weight: 600 !important;
        }

        [data-testid="stMetricDelta"] {
            font-weight: 600 !important;
        }

        /* Asegurar que los subtítulos y textos informativos tengan color oscuro */
        p, span, caption {
            color: #334155 !important;
        }
        </style>
    """, unsafe_allow_html=True)

    # Si HIZO CLIC en "Iniciar Sesión"
    if st.session_state["mostrar_login"]:
        _, col_centro, _ = st.columns([1, 1.4, 1])
        with col_centro:
            st.markdown("<br>", unsafe_allow_html=True)
            
            # Botón para volver al panel público
            if st.button("← Volver al Panel Público", key="btn_volver_login"):
                st.session_state["mostrar_login"] = False
                st.rerun()

            st.markdown("<br>", unsafe_allow_html=True)

                    
            # --- TARJETA CONTENEDORA MAESTRA CON DEGRADADO REAL ---
            st.markdown("""
                <div style="
                    background: linear-gradient(135deg, #1e3a8a, #2563eb);
                    border-radius: 14px 14px 0px 0px;
                    box-shadow: 0 10px 25px rgba(37, 99, 235, 0.25);
                    padding: 20px;
                    border: 1px solid #2563eb;
                ">
                    <!-- 1. Encabezado institucional -->
                    <div style="text-align: center; padding: 10px 0px 15px 0px;">
                        <div style="font-size: 45px; margin-bottom: 2px;">🏥</div>
                        <div style="color: #ffffff !important; font-size: 20px !important; font-weight: 700; letter-spacing: 0.5px; margin: 0px;">MR. CLAS COMBAPATA</div>
                        <div style="width: 80px; height: 3px; background: #ffffff; margin: 12px auto; border-radius: 20px; opacity: 0.85;"></div>
                        <div style="color: #ffffff !important; font-size: 15px !important; font-weight: 600; margin: 0px;">SISTEMA DE CONTROL DE FUAS OBSERVADAS</div>
                        <div style="color: #dbeafe !important; font-size: 12px !important; margin-top: 6px; margin-bottom: 0px;">Monitoreo y Corrección de Registros</div>
                    </div>
                    <div style="color: #ffffff !important; font-size: 14px; font-weight: 600; padding: 10px 0px 5px 0px;">
                        🔐 Acceso al Sistema
                        </div>

                        """, unsafe_allow_html=True)


            # 3. Formulario nativo de Streamlit (se renderiza dentro del flujo visual)
            with st.form("login_form_css_global"):
                username_input = st.text_input("Usuario", placeholder="Ingrese su usuario")
                password_input = st.text_input("Contraseña", type="password", placeholder="Ingrese su contraseña")

                st.markdown("<br>", unsafe_allow_html=True)
                submit_button = st.form_submit_button("Ingresar al Sistema", use_container_width=True)

                if submit_button:
                    if not username_input or not password_input:
                        st.warning("⚠️ Por favor completa todos los campos.")
                    else:
                        user_data = validar_login(username_input, password_input)
                        if user_data:
                            st.session_state["user"] = user_data
                            st.session_state["menu_activo"] = "Dashboard"
                            st.session_state["mostrar_login"] = False
                            st.success(f"¡Bienvenido/a, {user_data.get('nombre', 'Usuario')}!")
                            st.rerun()
                        else:
                            st.error("❌ Usuario o contraseña incorrectos.")

            # 4. Pie de página institucional y cierre de la tarjeta
            st.markdown("""
                <!-- Pie de página acoplado sin espacio en blanco -->
                <div style="
                    background: linear-gradient(135deg, #1e3a8a, #2563eb);
                    text-align: center; 
                    padding: 15px 10px; 
                    border-radius: 0px 0px 14px 14px;
                    border-top: 1px solid rgba(255, 255, 255, 0.15); 
                    margin-top: -22px;
                ">
                    <div style="color: #ffffff !important; font-size: 12px; font-weight: 700;">MÓDULO DE CONTROL DE FUAS - MR COMBAPATA</div>
                    <div style="color: #dbeafe !important; font-size: 11px; margin-top: 4px;">© 2026 • Todos los derechos reservados</div>
                    <div style="color: #93c5fd !important; font-size: 11px; margin-top: 2px;">Desarrollado por Joel Ch. F.</div>
                </div>
            """, unsafe_allow_html=True)
                                
        st.stop()

    # --- CASO 2: VISTA PÚBLICA ---
    else:
    # Encabezado superior y botón de login

        # --- CARGAR DATOS BASE DESDE POSTGRESQL ---
        @st.cache_data(ttl=30)
        def cargar_datos_base():
            conn = None
            try:
                conn = psycopg2.connect(
                    user=str(st.secrets["postgres"]["user"]),
                    password=str(st.secrets["postgres"]["password"]),
                    host=str(st.secrets["postgres"].get("host", "localhost")),
                    port=str(st.secrets["postgres"].get("port", "5432")),
                    database=str(st.secrets["postgres"]["database"])
                )
                
                df_est = pd.read_sql("SELECT id AS establecimiento_id, nombre_establecimiento FROM establecimientos;", conn)
                # Aseguramos traer la fecha de registro y fecha de corrección si existen
                df_fuas = pd.read_sql("""
                    SELECT id, establecimiento_id, estado, tipo_observacion, fecha_registro, fecha_correccion 
                    FROM fuas_observadas;
                """, conn)
                
                return df_est, df_fuas
            except Exception as e:
                # Fallback por si las columnas de fecha aún no están creadas en la BD
                try:
                    df_fuas = pd.read_sql("SELECT id, establecimiento_id, estado, tipo_observacion FROM fuas_observadas;", conn)
                    df_fuas["fecha_registro"] = pd.NaT
                    df_fuas["fecha_correccion"] = pd.NaT
                    return df_est, df_fuas
                except Exception as inner_e:
                    st.error(f"Error al conectar con la base de datos: {inner_e}")
                    return pd.DataFrame(), pd.DataFrame()
            finally:
                if conn is not None:
                    conn.close()

        df_est, df_fuas = cargar_datos_base()

        # Procesar fechas y uniones
        if not df_fuas.empty and not df_est.empty:
            df_merged = pd.merge(df_fuas, df_est, on="establecimiento_id", how="left")
            df_merged["Estado_Clean"] = df_merged["estado"].fillna("Pendiente").astype(str)
            
            # Convertir a datetime para filtros temporales
            df_merged["fecha_registro"] = pd.to_datetime(df_merged["fecha_registro"], errors="coerce")
            df_merged["fecha_correccion"] = pd.to_datetime(df_merged["fecha_correccion"], errors="coerce")
            
            df_merged["Anio"] = df_merged["fecha_registro"].dt.year
            df_merged["Mes"] = df_merged["fecha_registro"].dt.month_name()
        else:
            df_merged = pd.DataFrame(columns=["id", "establecimiento_id", "estado", "tipo_observacion", "nombre_establecimiento", "Estado_Clean", "fecha_registro", "fecha_correccion", "Anio", "Mes"])

        # --- PANEL DE FILTROS SUPERIORES (Establecimiento, Año y Mes) ---
        col_f1, col_f2, col_f3 = st.columns([3, 2, 2])
        
        lista_ee = ["Todos los Establecimientos"]
        if not df_est.empty and "nombre_establecimiento" in df_est.columns:
            lista_ee += sorted(df_est["nombre_establecimiento"].dropna().unique().tolist())

        anios_disponibles = ["Todos los Años"]
        if not df_merged.empty and "Anio" in df_merged.columns:
            anios_validos = df_merged["Anio"].dropna().unique()
            anios_disponibles += sorted([int(a) for a in anios_validos], reverse=True)

        meses_disponibles = ["Todos los Meses", "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"]

        with col_f1:
            ee_seleccionado = st.selectbox("🏥 Establecimiento:", lista_ee, key="filtro_ee")
        with col_f2:
            anio_seleccionado = st.selectbox("📅 Año:", anios_disponibles, key="filtro_anio")
        with col_f3:
            mes_seleccionado = st.selectbox("🗓️ Mes:", meses_disponibles, key="filtro_mes")

        st.markdown("<br>", unsafe_allow_html=True)

        # Diccionario de traducción de nombres de meses al número de mes (1-12)
        meses_map = {
            "Enero": 1, "Febrero": 2, "Marzo": 3, "Abril": 4,
            "Mayo": 5, "Junio": 6, "Julio": 7, "Agosto": 8,
            "Septiembre": 9, "Octubre": 10, "Noviembre": 11, "Diciembre": 12
        }

        # Extraer el número de mes numérico para filtrar con precisión
        if not df_merged.empty and "fecha_registro" in df_merged.columns:
            df_merged["Mes_Num"] = df_merged["fecha_registro"].dt.month
        else:
            df_merged["Mes_Num"] = None

        # --- APLICAR FILTROS EN MEMORIA ---
        df_filtered = df_merged.copy()

        if ee_seleccionado != "Todos los Establecimientos":
            df_filtered = df_filtered[df_filtered["nombre_establecimiento"] == ee_seleccionado]
        if anio_seleccionado != "Todos los Años":
            df_filtered = df_filtered[df_filtered["Anio"] == anio_seleccionado]
        if mes_seleccionado != "Todos los Meses":
            mes_num_sel = meses_map.get(mes_seleccionado)
            df_filtered = df_filtered[df_filtered["Mes_Num"] == mes_num_sel]

        # Calcular Métricas (KPIs)
        total_fuas = len(df_filtered)
        total_corregidas = len(df_filtered[df_filtered["Estado_Clean"].str.lower().str.contains("correg", na=False)]) if not df_filtered.empty else 0
        total_anuladas = len(df_filtered[df_filtered["Estado_Clean"].str.lower().str.contains("anul", na=False)]) if not df_filtered.empty else 0
        total_pendientes = len(df_filtered[df_filtered["Estado_Clean"].str.lower().str.contains("pend", na=False) | df_filtered["estado"].isna()]) if not df_filtered.empty else 0
        
        tasa_subsanacion = (total_corregidas / total_fuas * 100) if total_fuas > 0 else 0.0

        # Calcular Indicador de Eficiencia de Respuesta (Días promedio de subsanación)
        if not df_filtered.empty and "fecha_correccion" in df_filtered.columns and "fecha_registro" in df_filtered.columns:
            df_subs = df_filtered[df_filtered["fecha_correccion"].notna() & df_filtered["fecha_registro"].notna()]
            if not df_subs.empty:
                dias_diff = (df_subs["fecha_correccion"] - df_subs["fecha_registro"]).dt.days
                tiempo_promedio = round(dias_diff.mean(), 1)
            else:
                tiempo_promedio = 0.0
        else:
            tiempo_promedio = 0.0

        # --- 6 TARJETAS DE MÉTRICAS PRINCIPALES ---
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            st.metric(label="📄 Registradas", value=f"{total_fuas:,}", delta="Base activa")
        with col2:
            st.metric(label="⚠️ Pendientes", value=f"{total_pendientes:,}", delta="Por revisar", delta_color="inverse")
        with col3:
            st.metric(label="✅ Corregidas", value=f"{total_corregidas:,}", delta="Subsanadas")
        with col4:
            st.metric(label="❌ Anuladas", value=f"{total_anuladas:,}", delta="Bajas", delta_color="off")
        with col5:
            st.metric(label="⏱️ T. Promedio", value=f"{tiempo_promedio} días", delta="Eficiencia")
        with col6:
            st.metric(label="📈 Subsanación", value=f"{tasa_subsanacion:.1f}%", delta="Eficacia")

        st.markdown("<br>", unsafe_allow_html=True)


        if not df_filtered.empty:
            df_ee_ss = df_filtered.groupby(["nombre_establecimiento", "Estado_Clean"]).size().reset_index(name="Cantidad")
            df_ee_ss.rename(columns={"nombre_establecimiento": "Establecimiento", "Estado_Clean": "Estado"}, inplace=True)
        else:
            df_ee_ss = pd.DataFrame(columns=["Establecimiento", "Estado", "Cantidad"])

        # --- SECCIÓN DE GRÁFICOS Y TENDENCIAS ---
        col_izq, col_der = st.columns(2)

        with col_izq:
            st.markdown("#### 📈 FUAs por Establecimiento y Estado")
            if df_ee_ss is not None and not df_ee_ss.empty and df_ee_ss["Cantidad"].sum() > 0:
                import altair as alt
                
                domain = ['Pendiente', 'Corregido', 'Anulado']
                range_colors = ['#facc15', '#22c55e', '#ef4444']  # Amarillo, Verde, Rojo
                
                chart_bar = (
                    alt.Chart(df_ee_ss)
                    .mark_bar()
                    .encode(
                        x=alt.X(
                            'Establecimiento:N',
                            title='Establecimiento',
                            axis=alt.Axis(
                                labelColor='#111827',
                                titleColor='#111827',
                                labelFontSize=12,
                                titleFontSize=14
                            )
                        ),
                        y=alt.Y(
                            'Cantidad:Q',
                            title='Cantidad',
                            axis=alt.Axis(
                                labelColor='#111827',
                                titleColor='#111827',
                                labelFontSize=12,
                                titleFontSize=14
                            )
                        ),
                        color=alt.Color(
                            'Estado:N',
                            scale=alt.Scale(
                                domain=domain,
                                range=range_colors
                            ),
                            title='Estado',
                            legend=alt.Legend(
                                labelColor='#111827',
                                titleColor='#111827',
                                labelFontSize=12,
                                titleFontSize=14
                            )
                        ),
                        tooltip=['Establecimiento', 'Estado', 'Cantidad']
                    )
                    .properties(
                        height=350
                    )
                    .configure(
                        background='#ffffff'
                    )
                    .configure_axis(
                        grid=True,
                        gridColor='#d1d5db',
                        domainColor='#374151',
                        tickColor='#374151',
                        labelColor='#111827',
                        titleColor='#111827'
                    )
                    .configure_view(
                        stroke=None
                    )
                    .interactive()
                )
                
                st.altair_chart(chart_bar, use_container_width=True)
            else:
                st.info("ℹ️ No hay registros suficientes para mostrar el gráfico en este establecimiento.")

        with col_der:
            st.markdown("#### 📉 Tendencia Temporal de Observaciones")
            if not df_filtered.empty and "fecha_registro" in df_filtered.columns:
                import altair as alt
                
                df_tendencia = df_filtered.dropna(subset=["fecha_registro"]).copy()
                if not df_tendencia.empty:
                    df_tendencia["Periodo"] = df_tendencia["fecha_registro"].dt.to_period("M").astype(str)
                    df_tendencia_grp = df_tendencia.groupby("Periodo").size().reset_index(name="Cantidad")
                    
                    chart_line = (
                        alt.Chart(df_tendencia_grp)
                        .mark_line(
                            point=True,
                            color="#2563eb",
                            strokeWidth=3
                        )
                        .encode(
                            x=alt.X(
                                'Periodo:N',
                                title='Periodo (Mes/Año)',
                                axis=alt.Axis(
                                    labelColor='#111827',
                                    titleColor='#111827',
                                    labelFontSize=12,
                                    titleFontSize=14
                                )
                            ),
                            y=alt.Y(
                                'Cantidad:Q',
                                title='Nº Observaciones',
                                axis=alt.Axis(
                                    labelColor='#111827',
                                    titleColor='#111827',
                                    labelFontSize=12,
                                    titleFontSize=14
                                )
                            ),
                            tooltip=['Periodo', 'Cantidad']
                        )
                        .properties(
                            height=350
                        )
                        .configure(
                            background="#FFFFFF"
                        )
                        .configure_axis(
                            grid=True,
                            gridColor="#D1D5DB",
                            domainColor="#374151",
                            tickColor="#374151",
                            labelColor="#111827",
                            titleColor="#111827"
                        )
                        .configure_view(
                            stroke=None
                        )
                        .interactive()
                    )
                    
                    st.altair_chart(chart_line, use_container_width=True)
                else:
                    st.info("ℹ️ No hay fechas registradas para generar la tendencia.")
            else:
                st.info("ℹ️ Datos de tendencia no disponibles.")
            

            st.markdown("<br>", unsafe_allow_html=True)

        # --- TABLA DE MOTIVOS ---
        st.markdown("#### 📋 Principales Motivos de Observación")

        if not df_filtered.empty:
            df_motivos = df_filtered.groupby("tipo_observacion").size().reset_index(name="Cantidad")
            df_motivos.rename(columns={"tipo_observacion": "Motivo de Observación"}, inplace=True)
            df_motivos = df_motivos.sort_values(by="Cantidad", ascending=False)

            def zebra_rows(row):
                color = "#FFFFFF" if row.name % 2 == 0 else "#F3F4F6"
                return [f"background-color: {color}" for _ in row]

            styled_df = (
                df_motivos.style
                .apply(zebra_rows, axis=1)
                .set_properties(**{
                    "color": "#000000",
                    "border-bottom": "1px solid #E5E7EB"
                })
                .set_properties(
                    subset=["Cantidad"],
                    **{
                        "text-align": "center",
                        "font-weight": "bold"
                    }
                )
                .set_table_styles([
                    {
                        "selector": "th",
                        "props": [
                            ("background-color", "#0F172A"),
                            ("color", "white"),
                            ("font-size", "14px"),
                            ("font-weight", "bold"),
                            ("text-align", "center")
                        ]
                    }
                ])
                .highlight_max(
                    subset=["Cantidad"],
                    color="#D1FAE5"
                )
            )

            st.dataframe(
                styled_df,
                use_container_width=True,
                hide_index=True
            )


        else:
            st.info("ℹ️ No hay motivos registrados con los filtros seleccionados.")
    
    

        st.markdown("<br>", unsafe_allow_html=True)
        
        # Pie de página público
        st.markdown("""
            <div style="text-align: center; padding: 15px; color: #64748b; font-size: 12px; border-top: 1px solid #cbd5e1; margin-top: 30px;">
                <b>MR. CLAS COMBAPATA</b><br>
                Módulo de Control y Monitoreo de Registros FUA Observada • Elaborado por Joel CH. F.
            </div>
        """, unsafe_allow_html=True)
    

# --- CASO 3: USUARIO LOGUEADO (VISTA PRIVADA / ADMINISTRATIVA) ---
else:
    user = st.session_state["user"]
    
    # Extraemos los datos del usuario de forma segura con respaldos
    nombre_usuario = (
        user.get("nombre") or 
        user.get("nombres") or 
        user.get("nombre_completo") or 
        user.get("username") or 
        "Usuario Activo"
    )
    
    es_admin_user = user.get("es_admin", False)
    user_rol = user.get("rol", "Administrador" if es_admin_user else "Digitador")

    # 👤 Mostrar el usuario activo y su rol en un recuadro en la barra lateral
    st.sidebar.markdown(f"""
        <div style="
            padding: 12px; 
            border-radius: 8px; 
            border: 1px solid rgba(150, 150, 150, 0.3); 
            background-color: rgba(150, 150, 150, 0.08); 
            margin-bottom: 15px;
        ">
            <div style="font-size: 11px; color: gray; margin-bottom: 3px; text-transform: uppercase; letter-spacing: 0.5px;">Usuario Activo</div>
            <div style="font-size: 14px; font-weight: bold; margin-bottom: 6px;">👤 {nombre_usuario}</div>
            <span style="
                display: inline-block; 
                padding: 2px 8px; 
                background-color: #0066cc; 
                color: white; 
                border-radius: 4px; 
                font-size: 11px; 
                font-weight: bold;
                letter-spacing: 0.5px;
            ">
                {user_rol.upper()}
            </span>
        </div>
    """, unsafe_allow_html=True)
    st.sidebar.markdown("---")

    # =====================================================
    # APARIENCIA / SISTEMA DE TEMAS
    # =====================================================
    st.sidebar.markdown("""
    <div style="
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: #888;
        margin-top: 10px;
        margin-bottom: 8px;
        text-transform: uppercase;
    ">
        Apariencia
    </div>
    """, unsafe_allow_html=True)

    

    tema_seleccionado = st.sidebar.selectbox(
        "Seleccionar Tema Visual",
        list(TEMAS_DISPONIBLES.keys()),
        label_visibility="collapsed"
    )

    estilos = TEMAS_DISPONIBLES[tema_seleccionado]
    apply_theme_css(estilos)

    # Variables reutilizables para Altair
    CHART_BG = estilos["chart_bg"]
    CHART_TEXT = estilos["chart_text"]
    CHART_GRID = estilos["chart_grid"]
    CHART_BORDER = estilos["chart_border"]

    # =====================================================
    # CSS DINÁMICO
    # =====================================================

    # # st.markdown(f"""
    # <style>

    # /* Fondo general */
    # [data-testid="stAppViewContainer"] {{
    #     background-color: {estilos["bg_app"]} !important;
    # }}

    # .main {{
    #     background-color: {estilos["bg_app"]} !important;
    # }}

    # body {{
    #     color: {estilos["text_main"]} !important;
    # }}

    # /* Sidebar */
    # [data-testid="stSidebar"] {{
    #     background-color: {estilos["bg_sidebar"]} !important;
    #     border-right: 1px solid {estilos["border_card"]} !important;
    # }}

    # /* Títulos */
    # h1,h2,h3,h4,h5,h6 {{
    #     color: {estilos["text_main"]} !important;
    #     font-weight: 600 !important;
    # }}

    # /* Labels */
    # label,
    # [data-testid="stMetricLabel"] {{
    #     color: {estilos["text_sub"]} !important;
    # }}

    # /* Inputs */
    # input,
    # textarea,
    # div[data-baseweb="select"] > div,
    # div[data-baseweb="base-input"],
    # div[data-baseweb="input"],
    # div[data-baseweb="calendar"] {{

    #     background-color: {estilos["input_bg"]} !important;
    #     color: {estilos["input_text"]} !important;

    #     border: 1px solid {estilos["border_card"]} !important;
    #     border-radius: 6px !important;
    # }}

    # /* Selectbox */
    # div[data-baseweb="select"] * {{
    #     color: {estilos["input_text"]} !important;
    # }}

    # /* Date Input */
    # [data-testid="stDateInput"] input {{
    #     color: {estilos["input_text"]} !important;
    # }}

    # /* Focus */
    # div[data-baseweb="input"]:focus-within,
    # div[data-baseweb="select"]:focus-within > div {{

    #     border-color: {estilos["accent"]} !important;
    #     box-shadow: 0 0 0 3px rgba(47,129,247,0.2) !important;
    # }}

    # /* DataFrame */
    # [data-testid="stDataFrame"],
    # [data-testid="stTable"],
    # .stDataFrame {{

    #     background-color: {estilos["bg_card"]} !important;

    #     border: 1px solid {estilos["border_card"]} !important;
    #     border-radius: 10px !important;

    #     color: {estilos["text_main"]} !important;
    # }}

    # /* Botones generales */
    # .stButton > button {{

    #     background-color: {estilos["accent"]} !important;
    #     color: white !important;

    #     border: 1px solid {estilos["border_card"]} !important;
    #     border-radius: 8px !important;

    #     font-weight: 600 !important;
    # }}

    # .stButton > button:hover {{
    #     opacity: .92 !important;
    # }}

    # /* Sidebar botones */
    # [data-testid="stSidebar"] .stButton > button {{

    #     background-color: {estilos["bg_card"]} !important;
    #     color: {estilos["text_main"]} !important;

    #     text-align: left !important;

    #     border: 1px solid {estilos["border_card"]} !important;
    # }}

    # [data-testid="stSidebar"] .stButton > button:hover {{

    #     background-color: {estilos["hover_bg"]} !important;
    #     border-color: {estilos["hover_border"]} !important;
    # }}

    # /* Ocultar componentes */
    # #MainMenu {{
    #     visibility: hidden;
    # }}

    # footer {{
    #     visibility: hidden;
    # }}

    # button[title*="Deploy"] {{
    #     display: none !important;
    # }}

    # </style>
    # """, unsafe_allow_html=True)






    # Obtenemos el nombre del usuario desde el diccionario (si no existe, usa un valor por defecto)
    nombre_usuario = user.get("nombre", "Usuario")

    # Menú Lateral estilo Botones por Secciones

    if st.sidebar.button("📊 Dashboard", width="stretch"):
        st.session_state["menu_activo"] = "Dashboard"


    # --- MENÚ DE ADMINISTRACIÓN (SOLO PARA ADMINS) ---
    if es_admin_user:
        st.sidebar.markdown("**ADMINISTRACIÓN**")

        if st.sidebar.button("👥 Registrar Usuario", width="stretch"):
            st.session_state["menu_activo"] = "Registrar Usuario"

        if st.sidebar.button("✏️ Gestionar Usuarios", width="stretch"):
            st.session_state["menu_activo"] = "Gestionar Usuarios"

        if st.sidebar.button("🏥 Establecimientos", width="stretch"):
            st.session_state["menu_activo"] = "Establecimientos"

        if st.sidebar.button("👨‍⚕️ Profesionales", width="stretch"):
            st.session_state["menu_activo"] = "Profesionales"

        if st.sidebar.button("📤 Cargar ARFSIS-Web", width="stretch"):
            st.session_state["menu_activo"] = "Cargar ARFSIS-Web"

        if st.sidebar.button("💾 Backup", width="stretch"):
            st.session_state["menu_activo"] = "Backup"
            


    # --- MENÚ DE REGISTRO Y CONTROL (VISIBLE PARA TODOS) ---
    st.sidebar.markdown("**REGISTRO Y CONTROL**")
    if st.sidebar.button("📝 Registrar FUA", width="stretch"):
        st.session_state["menu_activo"] = "Registrar FUA"

    if st.sidebar.button("📋 Bandeja de Control", width="stretch"):
        st.session_state["menu_activo"] = "Bandeja de Control"

    if st.sidebar.button("📊 Sincronizacion ARFSIS-Web", width="stretch"):
        st.session_state["menu_activo"] = "Sincronizacion ARFSIS-Web"

    if st.sidebar.button("🪪 Afiliados", width="stretch"):
        st.session_state["menu_activo"] = "Afiliados"

    if st.sidebar.button("📦 Entregar Cargo", use_container_width=True):
        st.session_state["menu_activo"] = "Entregar Cargo"


    # --- MENÚ DE REPORTES ---
    st.sidebar.markdown("**REPORTES**")
    if st.sidebar.button("📊 Reportes y Estadísticas", width="stretch"):
        st.session_state["menu_activo"] = "Reportes y Estadísticas"


    # --- CERRAR SESIÓN ---
    if st.sidebar.button("🚪 Cerrar Sesión", width="stretch"):
        st.session_state["user"] = None
        st.rerun()


    # ---------------------------------------------------------
    # RENDERIZADO DE LAS VISTAS SEGÚN EL BOTÓN CLICKEADO
    # ---------------------------------------------------------
    vista_actual = st.session_state.get("menu_activo", "Dashboard") 


    if vista_actual == "Dashboard":
        render_dashboard(estilos)


    if vista_actual == "Registrar Usuario" and es_admin_user:
        st.subheader("👥 Registrar Nuevo Usuario")
        with st.form("form_nuevo_usuario", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                nuevo_dni = st.text_input("DNI (Clave Principal)", max_chars=15)
                nuevo_username = st.text_input("Nombre de Usuario (Login)")
            with col2:
                nuevo_nombre = st.text_input("Nombres y Apellidos Completos")
                nuevo_password = st.text_input("Contraseña temporal", type="password")

            tipo_rol = st.selectbox(
                "Tipo de Rol en el Sistema",
                options=["Digitador", "Auditora", "Administrador"],
                index=0
            )

            btn_crear = st.form_submit_button("Registrar Usuario")
            if btn_crear:
                if not nuevo_dni or not nuevo_username or not nuevo_password or not nuevo_nombre:
                    st.warning("Por favor completa todos los campos obligatorios.")
                else:
                    exito, mensaje = registrar_nuevo_usuario(
                        nuevo_dni, nuevo_username, nuevo_password, nuevo_nombre, tipo_rol
                    )
                    if exito:
                        st.success(mensaje)
                        st.rerun()
                    else:
                        st.error(mensaje)

    elif vista_actual == "Gestionar Usuarios" and es_admin_user:
        st.subheader("✏️ Lista de Usuarios ")
        usuarios_db = obtener_usuarios()
        if usuarios_db:
            df_usuarios = pd.DataFrame(usuarios_db, columns=["DNI", "Usuario", "Nombre Completo", "Rol", "Activo", "Creado En"])
            df_visual = df_usuarios.copy()
            df_visual["Activo"] = df_visual["Activo"].apply(lambda x: "Activo ✅" if x else "Inactivo ❌")
            st.dataframe(df_visual, use_container_width=True)

            st.divider()
            st.markdown("### ⚙️ Modificar o Eliminar un Usuario")
            lista_dnis = df_usuarios["DNI"].tolist()
            dni_seleccionado = st.selectbox("Seleccione el DNI del usuario a gestionar:", options=lista_dnis)

            if dni_seleccionado:
                user_row = df_usuarios[df_usuarios["DNI"] == dni_seleccionado].iloc[0]
                with st.form("form_editar_usuario"):
                    edit_dni = st.text_input("DNI (No modificable)", value=str(user_row["DNI"]), disabled=True)
                    edit_username = st.text_input("Nombre de Usuario", value=str(user_row["Usuario"]))
                    edit_nombre = st.text_input("Nombre Completo", value=str(user_row["Nombre Completo"]))

                    roles_opts = ["Digitador", "Auditora", "Administrador"]
                    rol_actual = str(user_row["Rol"])
                    idx_rol = roles_opts.index(rol_actual) if rol_actual in roles_opts else 0

                    edit_rol = st.selectbox("Tipo de Rol", options=roles_opts, index=idx_rol)
                    edit_activo = st.checkbox("Usuario Activo", value=bool(user_row["Activo"]))
                    edit_password = st.text_input("Nueva contraseña (Opcional)", type="password")

                    col_btn1, col_btn2 = st.columns(2)
                    with col_btn1:
                        btn_actualizar = st.form_submit_button("💾 Guardar Cambios")
                    with col_btn2:
                        btn_eliminar = st.form_submit_button("🗑️ Eliminar Usuario")

                    if btn_actualizar:
                        ok, msg = actualizar_usuario(dni_seleccionado, edit_username, edit_nombre, edit_rol, edit_activo, edit_password)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
                    if btn_eliminar:
                        if dni_seleccionado == user["dni"]:
                            st.error("No puedes eliminar tu propio usuario activo.")
                        else:
                            ok, msg = eliminar_usuario(dni_seleccionado)
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
        else:
            st.info("No hay usuarios registrados.")

    elif vista_actual == "Establecimientos" and es_admin_user:
        st.subheader("🏥 Gestión de Establecimientos de Salud")
        st.markdown("---")

        # Pestañas para organizar la creación y la gestión
        tab_lista, tab_nuevo = st.tabs(["📋 Lista de Establecimientos", "➕ Registrar Nuevo Establecimiento"])

        with tab_nuevo:
            st.markdown("### Registrar Nuevo Establecimiento")
            with st.form("form_nuevo_establecimiento", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    input_renaes = st.text_input("Código RENAES", max_chars=20, placeholder="Ej. 00001234")
                with col2:
                    input_nom_est = st.text_input("Nombre del Establecimiento", placeholder="Ej. P.S. San Juan de Dios")

                btn_guardar_est = st.form_submit_button("Guardar Establecimiento", type="primary")
                if btn_guardar_est:
                    if not input_renaes.strip() or not input_nom_est.strip():
                        st.warning("⚠️ Todos los campos son obligatorios.")
                    else:
                        ok, msg = registrar_establecimiento(input_renaes, input_nom_est)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

        with tab_lista:
            st.markdown("### Establecimientos Registrados en la Red")
            estab_db = obtener_todos_establecimientos()

            if estab_db:
                df_estab = pd.DataFrame(estab_db, columns=["ID", "Código RENAES", "Nombre del Establecimiento", "Activo"])
                df_estab_visual = df_estab.copy()
                df_estab_visual["Activo"] = df_estab_visual["Activo"].apply(lambda x: "Activo ✅" if x else "Inactivo ❌")

                st.dataframe(df_estab_visual, use_container_width=True)

                st.divider()
                st.markdown("### ⚙️ Modificar Establecimiento")

                lista_nombres_est = [f"ID: {row['ID']} | {row['Nombre del Establecimiento']} (RENAES: {row['Código RENAES']})" for _, row in df_estab.iterrows()]
                est_seleccionado_str = st.selectbox("Seleccione un establecimiento para editar:", options=lista_nombres_est)

                if est_seleccionado_str:
                    id_est_sel = int(est_seleccionado_str.split("|")[0].replace("ID:", "").strip())
                    row_est = df_estab[df_estab["ID"] == id_est_sel].iloc[0]

                    with st.form("form_editar_establecimiento"):
                        edit_renaes = st.text_input("Código RENAES", value=str(row_est["Código RENAES"]))
                        edit_nombre = st.text_input("Nombre del Establecimiento", value=str(row_est["Nombre del Establecimiento"]))
                        edit_activo = st.checkbox("Establecimiento Activo", value=bool(row_est["Activo"]))

                        btn_actualizar_est = st.form_submit_button("💾 Actualizar Establecimiento", type="primary")
                        if btn_actualizar_est:
                            ok, msg = actualizar_establecimiento(id_est_sel, edit_renaes, edit_nombre, edit_activo)
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
            else:
                st.info("No hay establecimientos registrados en el sistema.")

    elif vista_actual == "Registrar FUA":
        st.subheader("📝 Gestión de FUAs Observadas")
        st.markdown("---")

        # Reemplazamos la vista plana por dos pestañas principales
        tab_registro, tab_actualizar = st.tabs(["➕ Registrar Nueva FUA", "✏️ Actualizar FUA Observada"])

        # =========================================================================
        # PESTAÑA 1: REGISTRAR NUEVA FUA (TU CÓDIGO ACTUAL)
        # =========================================================================
        with tab_registro:
            # ------------------------------------
            # DEFINIR MODAL DE ÉXITO (VENTANA FLOTANTE)
            # ------------------------------------
            @st.dialog("¡Registro Exitoso! 🎉")
            def mostrar_modal_exito(nro_fua):
                st.success(f"La FUA N° **{nro_fua}** ha sido registrada correctamente.")
                st.write("Haz clic en Aceptar para limpiar el formulario y registrar otra FUA.")
                
                if st.button("Aceptar", use_container_width=True, type="primary"):
                    # Limpiamos las variables de estado para vaciar los campos
                    st.session_state["paciente_encontrado"] = None
                    st.session_state["dni_búsqueda_input"] = ""
                    st.session_state["input_nombre"] = ""
                    st.session_state["input_appaterno"] = ""
                    st.session_state["input_apmaterno"] = ""
                    st.session_state["input_num_fua"] = ""
                    st.session_state["input_tipo_obs"] = ""
                    st.session_state["input_det_obs"] = ""
                    st.rerun()


            # ------------------------------------
            # INICIALIZAR ESTADOS DE LOS INPUTS
            # ------------------------------------
            if "paciente_encontrado" not in st.session_state:
                st.session_state["paciente_encontrado"] = None

            # ------------------------------------
            # BLOQUE 1: BÚSQUEDA Y AUTOCOMPLETADO
            # ------------------------------------
            st.markdown("#### 1. Datos del Paciente / Afiliado")

            col_dni_search, col_btn_search = st.columns([3, 1])
            with col_dni_search:
                dni_input = st.text_input("DNI del Paciente", max_chars=15, key="dni_búsqueda_input")
            
            
            with col_btn_search:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔍 Buscar DNI", use_container_width=True):
                    if dni_input.strip():
                        res = buscar_afiliado_por_dni(dni_input.strip())
                        if res:
                            st.session_state["paciente_encontrado"] = res

                            # Asignamos los textos a las keys directamente
                            st.session_state["input_nombre"] = res[1] if res[1] else ""
                            st.session_state["input_appaterno"] = res[2] if res[2] else ""
                            st.session_state["input_apmaterno"] = res[3] if res[3] else ""

                            # Convertimos y asignamos la fecha directamente a la key del date_input
                            f_nac_raw = res[4] if len(res) > 4 else None
                            if f_nac_raw:
                                import pandas as pd

                                fecha_conv = pd.to_datetime(f_nac_raw, errors="coerce")
                                if not pd.isna(fecha_conv):
                                    st.session_state["input_fnac"] = fecha_conv.date()
                                else:
                                    st.session_state["input_fnac"] = None
                            else:
                                st.session_state["input_fnac"] = None

                            st.success("¡Paciente encontrado en el padrón!")
                        else:
                            st.session_state["paciente_encontrado"] = "NO_ENCONTRADO"
                            st.session_state["input_nombre"] = ""
                            st.session_state["input_appaterno"] = ""
                            st.session_state["input_apmaterno"] = ""
                            st.session_state["paciente_fnac_temp"] = None
                            st.warning("DNI no encontrado. Ingrese los datos manualmente.")

            # Valores por defecto para los inputs basados en la búsqueda
            paciente_dni = dni_input
            paciente_nombre = ""
            paciente_appaterno = ""
            paciente_apmaterno = ""
            paciente_fnac = None

            if isinstance(st.session_state.get("paciente_encontrado"), tuple):
                datos_p = st.session_state["paciente_encontrado"]
                st.session_state["val_nombre"] = datos_p[1] if datos_p[1] else ""
                st.session_state["val_appaterno"] = datos_p[2] if datos_p[2] else ""
                st.session_state["val_apmaterno"] = datos_p[3] if datos_p[3] else ""
                paciente_fnac = datos_p[4] if datos_p[4] else None
            elif st.session_state.get("paciente_encontrado") == "NO_ENCONTRADO":
                paciente_fnac = None
                st.session_state["val_nombre"] = ""
                st.session_state["val_appaterno"] = ""
                st.session_state["val_apmaterno"] = ""
            else:
                paciente_fnac = None
            if "val_nombre" not in st.session_state:
                st.session_state["val_nombre"] = ""
                st.session_state["val_appaterno"] = ""
                st.session_state["val_apmaterno"] = ""

            # 2. Renderizamos las columnas y los inputs usando el parámetro 'value=' de forma segura
            col_nom, col_appat, col_apmat, col_fnac = st.columns(4)

            with col_nom:
                input_nombre = st.text_input("Nombres", key="input_nombre")
            with col_appat:
                input_appaterno = st.text_input("Apellido Paterno", key="input_appaterno")
            with col_apmat:
                input_apmaterno = st.text_input("Apellido Materno", key="input_apmaterno")

            with col_fnac:
                import datetime
                import pandas as pd

                min_f_nac = datetime.date(1900, 1, 1)
                max_f_nac = datetime.date.today()

                # Recuperamos la fecha guardada en la sesión al buscar
                p_fnac = st.session_state.get("paciente_fnac_temp")
                valor_fecha_inicial = None
                if p_fnac:
                    fecha_convertida = pd.to_datetime(p_fnac, errors="coerce")
                    if not pd.isna(fecha_convertida):
                        valor_fecha_inicial = fecha_convertida.date()

                input_fnac = st.date_input(
                    "Fecha de Nacimiento",
                    value=valor_fecha_inicial,
                    min_value=min_f_nac,
                    max_value=max_f_nac,
                    format="DD/MM/YYYY",
                    key="input_fnac",
                )

            st.markdown("<br>", unsafe_allow_html=True)

            st.markdown("#### 2. Datos de la Atención y FUA")

            lista_est = obtener_lista_establecimientos()
            lista_prof = obtener_lista_profesionales()

            dict_est = {f"{nom}": id_est for id_est, nom in lista_est} if lista_est else {"Sin establecimientos registrados": None}
            dict_prof = {f"{nom} ({esp}) - DNI: {dni}": dni for dni, nom, esp in lista_prof} if lista_prof else {"Sin profesionales registrados": ""}

            # Fila 1: Número de FUA, Cód. Prestación y Fecha de Atención
            col_fua, col_cod_prest, col_fecha = st.columns([2, 1, 1])
            with col_fua:
                input_num_fua = st.text_input("Nº de FUA (Ej. 001-00012345)", max_chars=30, key="input_num_fua")
            with col_cod_prest:
                # Añadimos on_change para que dispare la búsqueda al presionar Enter o salir del campo
                input_id_prestacion = st.text_input(
                    "Cód. Prestación", 
                    placeholder="Ej. 056, 011", 
                    max_chars=20, 
                    key="input_id_prestacion",
                    on_change=actualizar_descripcion_automatica
                )
            with col_fecha:
                input_fecha_atencion = st.date_input(
                    "Fecha de Atención",
                    value=None,
                    format="DD/MM/YYYY"
                )

            # Fila 2: Descripción Completa de la Prestación 
            # (Se alimenta automáticamente de su propio key manejado por el callback)
            input_nombre_prestacion = st.text_input(
                "Descripción de la Prestación", 
                placeholder="Ej. Consulta externa por medicina general, Control prenatal, etc.", 
                key="input_nombre_prestacion"
            )

            # Fila 3: Establecimiento y Profesional
            col_est, col_prof = st.columns(2)
            with col_est:
                select_est = st.selectbox("Establecimiento de Salud", options=list(dict_est.keys()))
            with col_prof:
                select_prof = st.selectbox("Profesional de Salud Atendiente", options=list(dict_prof.keys()))

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### 3. Detalle de la Observación")

            col_cod_obs, col_det_obs = st.columns([1, 2])
            with col_cod_obs:
                input_tipo_obs = st.text_input("Tipo / Código de Observación", placeholder="Ej. OBS-01, DNI Inválido", key="input_tipo_obs")
            with col_det_obs:
                input_det_obs = st.text_area("Detalle / Sustento de la Observación", placeholder="Escriba la descripción exacta de la observación...", height=100, key="input_det_obs")

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("💾 Registrar FUA Observada", use_container_width=True, type="primary"):
                nro_fua_clean = input_num_fua.strip()
                
                # 1. Validaciones previas de campos obligatorios
                if not nro_fua_clean:
                    st.error("⚠️ El número de FUA es obligatorio.")
                elif not input_nombre.strip() or not input_appaterno.strip():
                    st.error("⚠️ Los nombres y el apellido paterno del paciente son obligatorios.")
                else:
                    # 2. Verificación previa de existencia para asegurar que el Nº de FUA sea único
                    fua_existente = buscar_fua_por_numero(nro_fua_clean)
                    if fua_existente:
                        st.warning(f"⚠️ La FUA N° **{nro_fua_clean}** ya se encuentra registrada en el sistema. Ingrese un número de FUA distinto.")
                    else:
                        id_est_sel = dict_est.get(select_est)
                        prof_dni_sel = dict_prof.get(select_prof)

                        datos_fua = {
                            "numero_fua": nro_fua_clean,
                            "id_prestacion": input_id_prestacion.strip(),
                            "nombre_prestacion": input_nombre_prestacion.strip(),
                            "establecimiento_id": id_est_sel,
                            "afiliado_dni": str(paciente_dni).strip(),
                            "afiliado_nombre": input_nombre.strip(),
                            "afiliado_appaterno": input_appaterno.strip(),
                            "afiliado_apmaterno": input_apmaterno.strip(),
                            "afiliado_fecha_nacimiento": input_fnac,
                            "profesional_dni": str(prof_dni_sel).strip() if prof_dni_sel else None,
                            "digitador_dni": user["dni"],
                            "tipo_observacion": input_tipo_obs.strip(),
                            "detalle_observacion": input_det_obs.strip(),
                            "fecha_atencion_fua": input_fecha_atencion if input_fecha_atencion else None
                        }

                        exito, msg = registrar_fua_observada(datos_fua)
                        if exito:
                            mostrar_modal_exito(nro_fua_clean)

        # =========================================================================
        # PESTAÑA 2: ACTUALIZAR FUAS OBSERVADAS (NUEVA PESTAÑA)
        # =========================================================================
        with tab_actualizar:
            st.markdown("#### 🔍 Búsqueda de FUA para Edición/Actualización")

            if "fua_encontrada_actualizar" not in st.session_state:
                st.session_state["fua_encontrada_actualizar"] = None

            col_search_fua, col_btn_fua = st.columns([3, 1])
            with col_search_fua:
                num_fua_edit = st.text_input("Ingrese Nº de FUA a Buscar", key="input_fua_search_edit")
            with col_btn_fua:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔎 Buscar FUA", use_container_width=True, key="btn_buscar_fua_edit"):
                    if num_fua_edit.strip():
                        fua_data = buscar_fua_por_numero(num_fua_edit.strip())
                        if fua_data:
                            st.session_state["fua_encontrada_actualizar"] = fua_data
                            st.success("¡FUA encontrada correctamente!")
                        else:
                            st.session_state["fua_encontrada_actualizar"] = None
                            st.warning("No se encontró ninguna FUA registrada con ese número.")
                    else:
                        st.info("Ingrese un número de FUA válido.")

            # Si se encontró la FUA en la BD, desplegamos todos los campos para su edición
            if st.session_state["fua_encontrada_actualizar"]:
                fua = st.session_state["fua_encontrada_actualizar"]
                st.markdown("---")
                st.markdown("### ✏️ Edición Completa de FUA Observada")

                # ------------------------------------
                # BLOQUE 1: DATOS DEL PACIENTE / AFILIADO
                # ------------------------------------
                st.markdown("#### 1. Datos del Paciente / Afiliado")
                u_paciente_dni = st.text_input("DNI del Paciente", value=fua.get("afiliado_dni") or "", max_chars=15, key="u_paciente_dni")

                col_u_nom, col_u_appat, col_u_apmat, col_u_fnac = st.columns(4)
                with col_u_nom:
                    u_input_nombre = st.text_input("Nombres", value=fua.get("afiliado_nombre") or "", key="u_input_nombre")
                with col_u_appat:
                    u_input_appaterno = st.text_input("Apellido Paterno", value=fua.get("afiliado_appaterno") or "", key="u_input_appaterno")
                with col_u_apmat:
                    u_input_apmaterno = st.text_input("Apellido Materno", value=fua.get("afiliado_apmaterno") or "", key="u_input_apmaterno")
                with col_u_fnac:
                    val_fnac = fua.get("afiliado_fecha_nacimiento")
                    u_input_fnac = st.date_input("Fecha de Nacimiento", value=val_fnac if val_fnac else None, key="u_input_fnac")

                st.markdown("<br>", unsafe_allow_html=True)
                # ------------------------------------
                # BLOQUE 2: DATOS DE LA ATENCIÓN Y FUA
                # ------------------------------------
                st.markdown("#### 2. Datos de la Atención y FUA")

                lista_est_u = obtener_lista_establecimientos()
                lista_prof_u = obtener_lista_profesionales()

                dict_est_u = {f"{nom}": id_est for id_est, nom in lista_est_u} if lista_est_u else {"Sin establecimientos registrados": None}
                dict_prof_u = {f"{nom} ({esp}) - DNI: {dni}": dni for dni, nom, esp in lista_prof_u} if lista_prof_u else {"Sin profesionales registrados": ""}

                # Fila 1: Nº de FUA, Cód. Prestación y Fecha de Atención
                col_u_fua, col_u_cod_prest, col_u_fecha = st.columns([2, 1, 1])
                with col_u_fua:
                    u_input_num_fua = st.text_input("Nº de FUA", value=fua.get("numero_fua") or "", max_chars=30, key="u_input_num_fua")
                with col_u_cod_prest:
                    u_input_id_prestacion = st.text_input("Cód. Prestación", value=fua.get("id_prestacion") or "", max_chars=20, key="u_input_id_prestacion")
                with col_u_fecha:
                    val_fatencion = fua.get("fecha_atencion_fua")
                    u_input_fecha_atencion = st.date_input("Fecha de Atención", value=val_fatencion if val_fatencion else None, key="u_input_fecha_atencion")

                # Fila 2: Descripción de la Prestación
                u_input_nombre_prestacion = st.text_input("Descripción de la Prestación", value=fua.get("nombre_prestacion") or "", key="u_input_nombre_prestacion")

                # Fila 3: Establecimiento y Profesional (¡Estos faltaban!)
                col_u_est, col_u_prof = st.columns(2)
                with col_u_est:
                    u_select_est = st.selectbox("Establecimiento de Salud", options=list(dict_est_u.keys()), key="u_select_est")
                with col_u_prof:
                    u_select_prof = st.selectbox("Profesional de Salud Atendiente", options=list(dict_prof_u.keys()), key="u_select_prof")

                st.markdown("<br>", unsafe_allow_html=True)
                # ------------------------------------
                # BLOQUE 3: DETALLE DE LA OBSERVACIÓN
                # ------------------------------------
                st.markdown("#### 3. Detalle de la Observación")

                col_u_cod_obs, col_u_det_obs = st.columns([1, 2])
                with col_u_cod_obs:
                    u_input_tipo_obs = st.text_input("Tipo / Código de Observación", value=fua.get("tipo_observacion") or "", key="u_input_tipo_obs")
                with col_u_det_obs:
                    u_input_det_obs = st.text_area("Detalle / Sustento de la Observación", value=fua.get("detalle_observacion") or "", height=100, key="u_input_det_obs")

                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔄 Actualizar Datos de FUA", use_container_width=True, type="primary", key="btn_actualizar_fua_completa"):
                    if not u_input_num_fua.strip():
                        st.error("⚠️ El número de FUA es obligatorio.")
                    elif not u_input_nombre.strip() or not u_input_appaterno.strip():
                        st.error("⚠️ Los nombres y el apellido paterno del paciente son obligatorios.")
                    else:
                        # Obtenemos los diccionarios actualizados de establecimientos y profesionales
                        lista_est_u = obtener_lista_establecimientos()
                        lista_prof_u = obtener_lista_profesionales()
                        dict_est_u = {f"{nom}": id_est for id_est, nom in lista_est_u} if lista_est_u else {}
                        dict_prof_u = {f"{nom} ({esp}) - DNI: {dni}": dni for dni, nom, esp in lista_prof_u} if lista_prof_u else {}

                        # Leemos de forma segura los valores seleccionados usando las claves (keys) de los selectbox
                        est_seleccionado_texto = st.session_state.get("u_select_est")
                        prof_seleccionado_texto = st.session_state.get("u_select_prof")

                        id_est_upd = dict_est_u.get(est_seleccionado_texto)
                        prof_dni_upd = dict_prof_u.get(prof_seleccionado_texto)

                        datos_actualizar = {
                            "id": fua["id"],
                            "numero_fua": u_input_num_fua.strip(),
                            "id_prestacion": u_input_id_prestacion.strip(),
                            "nombre_prestacion": u_input_nombre_prestacion.strip(),
                            "establecimiento_id": id_est_upd,
                            "afiliado_dni": str(u_paciente_dni).strip(),
                            "afiliado_nombre": u_input_nombre.strip(),
                            "afiliado_appaterno": u_input_appaterno.strip(),
                            "afiliado_apmaterno": u_input_apmaterno.strip(),
                            "afiliado_fecha_nacimiento": u_input_fnac,
                            "profesional_dni": str(prof_dni_upd).strip() if prof_dni_upd else None,
                            "tipo_observacion": u_input_tipo_obs.strip(),
                            "detalle_observacion": u_input_det_obs.strip(),
                            "fecha_atencion_fua": u_input_fecha_atencion
                        }

                        exito_upd, msg_upd = actualizar_fua_observada(datos_actualizar)
                        if exito_upd:
                            st.success("¡Los datos de la FUA han sido actualizados correctamente! 🎉")
                            st.session_state["fua_encontrada_actualizar"] = None
                            st.rerun()
                        else:
                            st.error(f"Error al actualizar la FUA: {msg_upd}")

    elif vista_actual == "Bandeja de Control":
        st.subheader("📥 Bandeja de Control de FUAs Observadas")
        st.markdown("---")

        # --- FILTROS ---
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            filtro_estado = st.selectbox("Filtrar por Estado", options=["Todos", "Pendiente", "Corregido", "Anulado", "Extemporáneo"])
        with col_f2:
            filtro_fua = st.text_input("Buscar por Nº FUA", placeholder="Ej. 451236")

        fuas_db = obtener_fuas_observadas()

        if fuas_db:
            df_fuas = pd.DataFrame(fuas_db, columns=[
            "ID", "Nº FUA", "Establecimiento", "DNI Paciente", "Paciente",
            "Profesional", "Tipo Observación", "Fecha Atención", "Estado", 
            "Fecha Registro", "Fecha Corrección", "Digitador DNI", "ID Prestación"
        ])

            col_f3, col_f4 = st.columns(2)
            
            with col_f3:
                lista_digitadores = ["Todos"] + sorted(df_fuas["Digitador DNI"].dropna().unique().tolist())
                filtro_digitador = st.selectbox("Filtrar por Digitador DNI", options=lista_digitadores)

            with col_f4:
                df_fuas["Fecha_Reg_Solo"] = pd.to_datetime(df_fuas["Fecha Registro"]).dt.date
                min_f = df_fuas["Fecha_Reg_Solo"].min()
                max_f = df_fuas["Fecha_Reg_Solo"].max()
                
                if pd.notna(min_f) and pd.notna(max_f):
                    rango_fechas = st.date_input(
                        "Filtrar por Rango de Fecha de Registro", 
                        value=(min_f, max_f),
                        format="DD/MM/YYYY"
                    )
                else:
                    rango_fechas = None

            st.markdown("---")

            # --- APLICAR FILTROS AL DATAFRAME ---
            if not df_fuas.empty:
                columnas_de_fecha = ["Fecha Registro", "Fecha Corrección", "Fecha Modificación", "Fecha Actualización"]

                for col in columnas_de_fecha:
                    if col in df_fuas.columns:
                        df_fuas[col] = pd.to_datetime(df_fuas[col], errors='coerce').dt.strftime("%d-%m-%Y %H:%M:%S")
                        df_fuas[col] = df_fuas[col].fillna("-")
               
               
               # 1. --- CÁLCULO DE ANTIGÜEDAD Y CAMBIO DE ESTADO (PRIMERO) ---
                hoy = pd.Timestamp.now().normalize().date()
                df_fuas["Fecha_Atencion_Solo"] = pd.to_datetime(df_fuas["Fecha Atención"]).dt.date
                
                def calcular_antiguedad(row):
                    if pd.notna(row["Fecha_Atencion_Solo"]):
                        delta = (hoy - row["Fecha_Atencion_Solo"]).days
                        return max(delta, 0) # Evita negativos por desfases
                    return 0 

                df_fuas["Días Pendiente"] = df_fuas.apply(calcular_antiguedad, axis=1)

                # 📌 REGLA AUTOMÁTICA: Cambiar Estado a Extemporáneo si supera los 45 días
                df_fuas.loc[(df_fuas["Días Pendiente"] > 45) & (df_fuas["Estado"] == "Pendiente"), "Estado"] = "Extemporáneo"


                # 2. --- APLICAR FILTROS DE LA INTERFAZ (DESPUÉS del cálculo) ---
                if filtro_estado != "Todos":
                    df_fuas = df_fuas[df_fuas["Estado"] == filtro_estado]

                if filtro_fua.strip():
                    df_fuas = df_fuas[
                        df_fuas["Nº FUA"].astype(str).str.contains(filtro_fua.strip(), case=False, na=False)
                    ]

                if filtro_digitador != "Todos":
                    df_fuas = df_fuas[df_fuas["Digitador DNI"] == filtro_digitador]

                if rango_fechas and isinstance(rango_fechas, tuple) and len(rango_fechas) == 2:
                    f_inicio, f_fin = rango_fechas
                    df_fuas = df_fuas[
                        (df_fuas["Fecha_Reg_Solo"] >= f_inicio) & 
                        (df_fuas["Fecha_Reg_Solo"] <= f_fin)
                    ]

                # 📌 --- GUARDAR EN SESIÓN PARA EL MÓDULO "ENTREGAR CARGO" ---
                st.session_state["df_fuas"] = df_fuas

                # 4. --- CONTADOR Y BOTÓN DE EXPORTACIÓN A EXCEL ---
                col_info, col_btn = st.columns([3, 1])
                with col_info:
                    st.markdown(f"Mostrando **{len(df_fuas)}** registros encontrados.")
                
                with col_btn:
                    import io
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='openpyxl') as writer:
                        df_fuas.drop(columns=["Fecha_Reg_Solo", "Fecha_Atencion_Solo"], errors="ignore").to_excel(writer, index=False, sheet_name="FUAs_Filtradas")
                    processed_data = output.getvalue()
                    
                    st.download_button(
                        label="📥 Exportar a Excel",
                        data=processed_data,
                        file_name="fuas_observadas_filtradas.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )

                # --- FUNCIÓN DE ESTILOS VISUALES ---
                def resaltar_filas(row):
                    styles = [""] * len(row)
                    estado = row["Estado"]
                    dias = row.get("Días Pendiente", 0)
                    
                    idx_estado = row.index.get_loc("Estado")
                    idx_dias = row.index.get_loc("Días Pendiente") if "Días Pendiente" in row.index else None

                    if estado == "Pendiente":
                        if dias > 25:
                            styles[idx_estado] = "color: #E74C3C; font-weight: bold;"
                            if idx_dias is not None:
                                styles[idx_dias] = "color: #E74C3C; font-weight: bold;"
                        else:
                            styles[idx_estado] = "color: #D4AC0D; font-weight: bold;"
                            if idx_dias is not None:
                                styles[idx_dias] = "color: #D4AC0D; font-weight: bold;"
                    elif estado == "Corregido":
                        styles[idx_estado] = "color: #2ECC71; font-weight: bold;"
                        if idx_dias is not None:
                            styles[idx_dias] = "color: #2ECC71;"
                    elif estado == "Anulado":
                        styles[idx_estado] = "color: #E74C3C; font-weight: bold;"
                        if idx_dias is not None:
                            styles[idx_dias] = "color: #E74C3C;"
                    elif estado == "Extemporáneo":
                        styles[idx_estado] = "color: #900C3F; font-weight: bold;"
                        if idx_dias is not None:
                            styles[idx_dias] = "color: #900C3F; font-weight: bold;"

                    return styles
                

                df_visual = df_fuas[[
                    "Nº FUA", "Establecimiento", "DNI Paciente", "Paciente", 
                    "Profesional", "Tipo Observación", "Fecha Atención", "Estado", "Días Pendiente", "Fecha Registro", "Fecha Corrección"
                ]].copy()

                df_styled = df_visual.style.apply(resaltar_filas, axis=1)
                st.dataframe(df_styled, use_container_width=True)

                st.divider()
                
                st.markdown("### ⚙️ Gestionar / Cambiar Estado de FUA")

                # Cambiamos el selectbox por una caja de texto para buscar directamente por número de FUA
                fua_buscada = st.text_input("Ingrese el número de FUA a gestionar:", placeholder="Ej. 49191119")

                if fua_buscada.strip():
                    # Filtramos las filas que coincidan con lo que vas escribiendo
                    df_encontrado = df_fuas[df_fuas["Nº FUA"].astype(str).str.contains(fua_buscada.strip(), case=False, na=False)]
                    
                    if not df_encontrado.empty:
                        # Si hay coincidencia(s), si es única la tomamos directo, o damos a elegir si hay varias
                        if len(df_encontrado) == 1:
                            row_actual = df_encontrado.iloc[0]
                        else:
                            lista_fua_opciones = [f"ID: {row['ID']} | FUA: {row['Nº FUA']} | Paciente: {row['Paciente']}" for _, row in df_encontrado.iterrows()]
                            fua_seleccionada_str = st.selectbox("Se encontraron varias coincidencias. Seleccione una:", options=lista_fua_opciones)
                            id_sel = int(fua_seleccionada_str.split("|")[0].replace("ID:", "").strip())
                            row_actual = df_fuas[df_fuas["ID"] == id_sel].iloc[0]

                        id_seleccionado = int(row_actual["ID"])

                        st.info(f"**FUA Seleccionada:** {row_actual['Nº FUA']} | **Paciente:** {row_actual['Paciente']} | **Estado Actual:** {row_actual['Estado']} | **Antigüedad:** {row_actual.get('Días Pendiente', '')} días")

                        # --- CAPTURAMOS EL DNI DEL USUARIO DESDE st.session_state["user"] ---
                        user_info = st.session_state.get("user", {})
                        dni_actual = user_info.get("dni") or user_info.get("username")

                        col_b1, col_b2, col_b3 = st.columns(3)

                        with col_b1:
                            st.markdown('<div class="btn-verde-custom">', unsafe_allow_html=True)
                            if st.button("✅ Marcar como Corregido", use_container_width=True):
                                ok, msg = actualizar_estado_fua(id_seleccionado, "Corregido", dni_actual)
                                if ok:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                            st.markdown('</div>', unsafe_allow_html=True)
                                
                        with col_b2:
                            st.markdown('<div class="btn-gris-custom">', unsafe_allow_html=True)
                            if st.button("🚫 Marcar como Anulado", use_container_width=True):
                                ok, msg = actualizar_estado_fua(id_seleccionado, "Anulado", dni_actual)
                                if ok:
                                    st.warning(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                            st.markdown('</div>', unsafe_allow_html=True)

                        with col_b3:
                            st.markdown('<div class="btn-rojo-custom">', unsafe_allow_html=True)
                            if st.button("⌛ Marcar como Pendiente", use_container_width=True):
                                ok, msg = actualizar_estado_fua(id_seleccionado, "Pendiente", dni_actual)
                                if ok:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                            st.markdown('</div>', unsafe_allow_html=True)

                        # --- SECCIÓN DE HISTORIAL Y AUDITORÍA ---
                        st.markdown("---")
                        with st.expander("📜 Ver Historial de Cambios de esta FUA"):
                            conn_hist = None
                            try:
                                conn_hist = init_connection()
                                cur_hist = conn_hist.cursor()
                                
                                id_limpio = int(id_seleccionado)
                                
                                # 1. Extraer los datos de creación original de la FUA desde row_actual
                                fecha_creacion = str(
                                    row_actual.get("fecha_registro") or 
                                    row_actual.get("Fecha Registro") or 
                                    row_actual.get("fecha_atencion_fua") or 
                                    "Fecha no disponible"
                                )
                                if hasattr(fecha_creacion, "strftime"):
                                    fecha_creacion = fecha_creacion.strftime("%d/%m/%Y %H:%M:%S")

                                dni_digitador = str(
                                    row_actual.get("digitador_dni") or 
                                    row_actual.get("Digitador DNI") or 
                                    ""
                                ).strip()
                                
                                nombre_digitador = dni_digitador
                                
                                # Buscar el nombre completo del usuario creador original
                                if dni_digitador:
                                    cur_hist.execute("""
                                        SELECT nombre_completo FROM usuarios 
                                        WHERE TRIM(dni::text) = TRIM(%s) OR TRIM(username::text) = TRIM(%s) 
                                        LIMIT 1
                                    """, (dni_digitador, dni_digitador))
                                    res_user = cur_hist.fetchone()
                                    if res_user and res_user[0]:
                                        nombre_digitador = res_user[0]

                                # 2. CREAR LA LISTA INICIAL obligatoriamente con el Registro Inicial arriba del todo
                                lista_movimientos = [
                                    (fecha_creacion, "Registro Inicial", "-", "Pendiente", nombre_digitador)
                                ]
                                
                                # 3. Consultar los cambios posteriores registrados en la base de datos
                                query_historial = """
                                    SELECT 
                                        TO_CHAR(h.fecha_movimiento, 'DD/MM/YYYY HH24:MI:SS') AS "Fecha y Hora",
                                        h.accion AS "Acción Realizada",
                                        COALESCE(h.estado_anterior, '-') AS "Estado Anterior",
                                        h.estado_nuevo AS "Estado Nuevo",
                                        COALESCE(u.nombre_completo, h.usuario_dni, '-') AS "Usuario"
                                    FROM fua_historial h
                                    LEFT JOIN usuarios u ON (
                                        TRIM(h.usuario_dni::text) = TRIM(u.dni::text) OR 
                                        TRIM(h.usuario_dni::text) = TRIM(u.username::text)
                                    )
                                    WHERE h.fua_id = %s AND h.accion != 'Registro Inicial'
                                    ORDER BY h.fecha_movimiento ASC;
                                """
                                
                                cur_hist.execute(query_historial, (id_limpio,))
                                filas_db = cur_hist.fetchall()
                                
                                # 4. Agregar los cambios posteriores debajo del registro inicial
                                for reg in filas_db:
                                    lista_movimientos.append((reg[0], reg[1], reg[2], reg[3], reg[4]))
                                
                                # 5. Convertir a DataFrame y mostrar en Streamlit
                                df_hist = pd.DataFrame(lista_movimientos, columns=[
                                    "Fecha y Hora", "Acción Realizada", "Estado Anterior", "Estado Nuevo", "Usuario"
                                ])
                                
                                if not df_hist.empty:
                                    st.dataframe(df_hist, use_container_width=True, hide_index=True)
                                else:
                                    st.info("No hay registros en el historial para esta FUA.")
                                    
                                cur_hist.close()
                            except Exception as err_h:
                                st.error(f"Error al cargar el historial: {err_h}")
                            finally:
                                if conn_hist:
                                    conn_hist.close()






                        # INYECTAR ESTILOS CSS
                        st.markdown("""
                        <style>
                            div.btn-verde-custom button {
                                background-color: #28a745 !important;
                                border-color: #28a745 !important;
                                color: #ffffff !important;
                            }
                            div.btn-verde-custom button:hover {
                                background-color: #218838 !important;
                                border-color: #1e7e34 !important;
                            }

                            div.btn-gris-custom button {
                                background-color: #6c757d !important;
                                border-color: #6c757d !important;
                                color: #ffffff !important;
                            }
                            div.btn-gris-custom button:hover {
                                background-color: #5a6268 !important;
                                border-color: #545b62 !important;
                            }

                            div.btn-rojo-custom button {
                                background-color: #dc3545 !important;
                                border-color: #dc3545 !important;
                                color: #ffffff !important;
                            }
                            div.btn-rojo-custom button:hover {
                                background-color: #c82333 !important;
                                border-color: #bd2130 !important;
                            }
                        </style>
                        """, unsafe_allow_html=True)
            else:
                st.info("No hay registros que coincidan con los filtros aplicados.")
        else:
            df_fuas = pd.DataFrame(columns=[
                "ID", "Nº FUA", "Establecimiento", "DNI Paciente", "Paciente",
                "Profesional", "Tipo Observación", "Fecha Atención", "Estado", 
                "Fecha Registro", "Fecha Corrección", "Digitador DNI", "Fecha_Reg_Solo"
            ])
            st.info("Aún no hay FUAs observadas registradas en el sistema.")
    

    elif st.session_state.get("menu_activo") == "Profesionales" and es_admin_user:
        st.subheader("👨‍⚕️ Gestión de Profesionales de Salud")
        st.markdown("---")

        tab_lista_prof, tab_nuevo_prof = st.tabs(["📋 Lista de Profesionales", "➕ Registrar Nuevo Profesional"])

        # Cargar lista de establecimientos activos para asignarlos al profesional
        lista_est = obtener_lista_establecimientos()
        dict_est_options = {est[1]: est[0] for est in lista_est} if lista_est else {}

        with tab_nuevo_prof:
            st.markdown("### Registrar Nuevo Profesional")
            with st.form("form_nuevo_profesional", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    input_dni_prof = st.text_input("DNI del Profesional", max_chars=15, placeholder="Ej. 12345678")
                    input_esp_prof = st.text_input("Profesión u Especialidad", placeholder="Ej. Médico General / Enfermera")
                with col2:
                    input_nom_prof = st.text_input("Nombres y Apellidos", placeholder="Ej. Juan Pérez Gómez")
                    if dict_est_options:
                        nombre_est_sel = st.selectbox("Establecimiento Asignado", options=list(dict_est_options.keys()))
                    else:
                        st.warning("Debe registrar establecimientos activos primero.")
                        nombre_est_sel = None

                btn_guardar_prof = st.form_submit_button("Guardar Profesional", type="primary")
                if btn_guardar_prof:
                    if not input_dni_prof.strip() or not input_nom_prof.strip() or not input_esp_prof.strip() or not nombre_est_sel:
                        st.warning("⚠️ Todos los campos son obligatorios.")
                    else:
                        est_id_fk = dict_est_options[nombre_est_sel]
                        ok, msg = registrar_profesional(input_dni_prof, input_nom_prof, input_esp_prof, est_id_fk)
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

        with tab_lista_prof:
            st.markdown("### Profesionales Registrados en la Red")

            # Consulta SQL para tu tabla de profesionales
            query_profs = """
                SELECT 
                    p.dni AS "DNI",
                    p.nombres_apellidos AS "Nombres y Apellidos",
                    p.profesion_o_especialidad AS "Especialidad",
                    COALESCE(e.nombre_establecimiento, p.establecimiento) AS "Establecimiento",
                    p.activo AS "Activo",
                    p.establecimiento AS "Establecimiento ID"
                FROM profesionales p
                LEFT JOIN establecimientos e ON (
                    CASE 
                        WHEN p.establecimiento ~ '^[0-9]+$' THEN p.establecimiento::integer 
                        ELSE NULL 
                    END = e.id
                )
                ORDER BY p.nombres_apellidos ASC;
            """

            try:
                # Usamos pandas directamente con tu conexión de base de datos existente (ej. conn o engine)
                # Si usas st.connection, asegúrate de que el secrets.toml tenga el bloque [connections.postgresql]
                import pandas as pd

                # Ejemplo usando tu función de conexión si ya la tienes en tu app:
                conn = init_connection() # O la variable de conexión que uses globalmente
                df_profs = pd.read_sql(query_profs, con=conn)
                # (Si usas un gestor que cierra la conexión, recuerda cerrarla o usar with conn:)

                if not df_profs.empty:
                    df_profs_visual = df_profs[["DNI", "Nombres y Apellidos", "Especialidad", "Establecimiento", "Activo"]].copy()
                    df_profs_visual["Activo"] = df_profs_visual["Activo"].apply(lambda x: "Activo ✅" if x else "Inactivo ❌")

                    st.dataframe(df_profs_visual, width="stretch", hide_index=True)

                    st.divider()
                    st.markdown("### ⚙️ Modificar Profesional")

                    lista_prof_opciones = [f"DNI: {row['DNI']} | {row['Nombres y Apellidos']} ({row['Especialidad']})" for _, row in df_profs.iterrows()]
                    prof_seleccionado_str = st.selectbox("Seleccione un profesional para editar:", options=lista_prof_opciones)

                    if prof_seleccionado_str:
                        dni_sel = prof_seleccionado_str.split("|")[0].replace("DNI:", "").strip()
                        row_prof = df_profs[df_profs["DNI"] == dni_sel].iloc[0]

                        with st.form("form_editar_profesional"):
                            edit_dni = st.text_input("DNI (No editable)", value=str(row_prof["DNI"]), disabled=True)
                            edit_nombres = st.text_input("Nombres y Apellidos", value=str(row_prof["Nombres y Apellidos"]))
                            edit_esp = st.text_input("Profesión u Especialidad", value=str(row_prof["Especialidad"]))

                            current_est_id = row_prof["Establecimiento ID"]
                            default_est_idx = 0
                            est_keys = list(dict_est_options.keys())
                            for idx, key in enumerate(est_keys):
                                if dict_est_options[key] == current_est_id:
                                    default_est_idx = idx
                                    break

                            edit_est_nombre = st.selectbox("Establecimiento Asignado", options=est_keys, index=default_est_idx if est_keys else 0)
                            edit_activo_prof = st.checkbox("Profesional Activo", value=bool(row_prof["Activo"]))

                            btn_actualizar_prof = st.form_submit_button("💾 Actualizar Profesional", type="primary")
                            if btn_actualizar_prof:
                                if not edit_nombres.strip() or not edit_esp.strip() or not edit_est_nombre:
                                    st.warning("⚠️ Complete todos los campos requeridos.")
                                else:
                                    nuevo_est_id = dict_est_options[edit_est_nombre]
                                    ok, msg = actualizar_profesional(dni_sel, edit_nombres, edit_esp, nuevo_est_id, edit_activo_prof)
                                    if ok:
                                        st.success(msg)
                                        st.rerun()
                                    else:
                                        st.error(msg)
                else:
                    st.info("No hay profesionales registrados en el sistema.")

            except Exception as e:
                st.error(f"Error al consultar la base de datos: {e}")

    elif vista_actual == "Reportes y Estadísticas":
        from theme import get_theme
        theme = get_theme(estilos)

        CARD_BG = theme["CARD_BG"]
        CARD_BORDER = theme["CARD_BORDER"]
        
        TEXT_MAIN = theme["TEXT_MAIN"]
        TEXT_SUB = theme["TEXT_SUB"]
        
        CHART_BG = theme["CHART_BG"]
        CHART_TEXT = theme["CHART_TEXT"]
        
        ACCENT = theme["ACCENT"]

        
        st.markdown(f"""
            <style>

            /* MÉTRICAS */

            [data-testid="stMetric"] {{
                background-color: {CARD_BG};
                border: 1px solid {CARD_BORDER};
                border-radius: 10px;
                padding: 12px;
            }}

            [data-testid="stMetricLabel"] {{
                color: {TEXT_SUB} !important;
            }}

            [data-testid="stMetricValue"] {{
                color: {TEXT_MAIN} !important;
            }}

            /* TABS */

            button[data-baseweb="tab"] {{
                color: {TEXT_MAIN} !important;
            }}

            /* DATAFRAME */

            [data-testid="stDataFrame"] {{
                background-color: {CARD_BG} !important;
            }}

            /* DOWNLOAD BUTTON */

            .stDownloadButton > button {{
                background-color: {ACCENT} !important;
                color: white !important;
                border-radius: 8px !important;
                border: none !important;
            }}

            </style>
            """, unsafe_allow_html=True)

        st.subheader("📊 Módulo de Reportes y Estadísticas")
        st.markdown("---")
        
        # Obtener métricas generales directamente (sin el botón general arriba)
        total, pendientes, corregidos = obtener_estadisticas_generales()
        
        # Tarjetas de métricas principales
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="📄 Total de FUAs Observadas", value=total if total is not None else 0)
        with col2:
            val_p = pendientes if pendientes is not None else 0
            st.metric(label="⌛ Total Pendientes", value=val_p, delta=f"-{val_p}" if val_p > 0 else "0", delta_color="inverse")
        with col3:
            val_c = corregidos if corregidos is not None else 0
            st.metric(label="✅ Total Corregidos", value=val_c, delta=f"+{val_c}" if val_c > 0 else "off", delta_color="off")
            
        st.divider()
        
        # --- DEFINICIÓN DE LAS 3 PESTAÑAS ---
        tab_est, tab_prof, tab_filtro_excel = st.tabs([
            "🏥 Reporte por Establecimiento", 
            "👨‍⚕️ Reporte por Profesional", 
            "📥 Filtros y Exportación Excel"
        ])
        
        # ==========================================
        # 1. CONTENIDO DE LA PESTAÑA 1
        # ==========================================
        with tab_est:
            st.markdown("### Consolidado por Establecimiento de Salud")
            datos_est = obtener_reporte_por_establecimiento()
            
            if datos_est:
                df_reporte_est = pd.DataFrame(
                    datos_est, 
                    columns=["Establecimiento", "Pendientes", "Corregidos", "Total"]
                )
                st.dataframe(df_reporte_est, use_container_width=True)
                
                # --- BOTÓN DE EXPORTAR A EXCEL PARA ESTABLECIMIENTO ---
                import io
                output_est = io.BytesIO()
                with pd.ExcelWriter(output_est, engine='openpyxl') as writer:
                    df_reporte_est.to_excel(writer, index=False, sheet_name='Reporte_Establecimientos')
                excel_est_bytes = output_est.getvalue()
                
                timestamp_est = datetime.now().strftime("%Y-%m-%d_%H-%M")
                
                st.download_button(
                    label="📥 Descargar Consolidado por Establecimiento (.xlsx)",
                    data=excel_est_bytes,
                    file_name=f"reporte_por_establecimiento_{timestamp_est}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    key="btn_download_est",
                    use_container_width=True
                )
                
                st.markdown("### 📈 Gráfico Comparativo por Establecimiento")
                df_chart_est = df_reporte_est.set_index("Establecimiento")[["Pendientes", "Corregidos"]]
                import plotly.express as px
                fig = px.bar(
                    df_reporte_est,
                    x="Establecimiento",
                    y=["Pendientes", "Corregidos"],
                    barmode="group"
                )

                fig.update_layout(
                    paper_bgcolor=CHART_BG,
                    plot_bgcolor=CHART_BG,
                    font=dict(color=CHART_TEXT),
                    template="plotly_white" if "Claro" in tema_seleccionado else "plotly_dark"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )
            else:
                st.info("No hay suficientes datos registrados por establecimiento.")
                
        # ==========================================
        # 2. CONTENIDO DE LA PESTAÑA 2
        # ==========================================
        with tab_prof:
            st.markdown("### Consolidado por Profesional Atendiente")
            datos_prof = obtener_reporte_por_profesional()
            
            if datos_prof:
                df_reporte_prof = pd.DataFrame(
                    datos_prof, 
                    columns=["Profesional", "Especialidad", "Establecimiento", "Pendientes", "Corregidos", "Total"]
                )
                st.dataframe(df_reporte_prof, use_container_width=True)
                
                # Botón de descarga exclusivo para esta pestaña
                import io
                output_prof = io.BytesIO()
                with pd.ExcelWriter(output_prof, engine='openpyxl') as writer:
                    df_reporte_prof.to_excel(writer, index=False, sheet_name='Reporte_Profesionales')
                excel_prof_bytes = output_prof.getvalue()
                
                timestamp_prof = datetime.now().strftime("%Y-%m-%d_%H-%M")
                
                st.download_button(
                    label="📥 Descargar Consolidado por Profesional (.xlsx)",
                    data=excel_prof_bytes,
                    file_name=f"reporte_por_profesional_{timestamp_prof}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    key="btn_download_prof",
                    use_container_width=True
                )
                
                st.markdown("### 📊 Gráfico Comparativo por Profesional")
                df_chart_prof = df_reporte_prof.set_index("Profesional")[["Pendientes", "Corregidos"]]
                st.bar_chart(df_chart_prof)
            else:
                st.info("No hay suficientes datos registrados asociados a profesionales.")

        # ==========================================
        # 3. CONTENIDO DE LA PESTAÑA 3 (Filtros y Excel con Todos los Campos)
        # ==========================================
        with tab_filtro_excel:
            st.markdown("### 🔍 Panel de Filtros y Reporte Detallado")
            st.markdown("Filtra por rango de fechas, establecimiento(s), profesional(es) y estado para visualizar y descargar los registros:")
            
            # Consultar listas de la BD para los selectores múltiples
            conn_tmp = init_connection()
            cur_tmp = conn_tmp.cursor()
            cur_tmp.execute("SELECT DISTINCT nombre_establecimiento FROM establecimientos WHERE nombre_establecimiento IS NOT NULL ORDER BY 1;")
            lista_est_db = [row[0] for row in cur_tmp.fetchall()]
            
            cur_tmp.execute("SELECT DISTINCT nombres_apellidos FROM profesionales WHERE nombres_apellidos IS NOT NULL ORDER BY 1;")
            lista_prof_db = [row[0] for row in cur_tmp.fetchall()]
            
            cur_tmp.execute("SELECT DISTINCT estado FROM fuas_observadas WHERE estado IS NOT NULL ORDER BY 1;")
            lista_estados_db = [row[0] for row in cur_tmp.fetchall()]
            
            cur_tmp.close()
            conn_tmp.close()

            # Distribución de filtros en columnas para mayor orden
            col_fx1, col_fx2 = st.columns(2)
            with col_fx1:
                rango_fechas_avanzado = st.date_input(
                    "Rango de Fechas:",
                    value=(datetime(2026, 1, 1), datetime.today()),
                    format="DD/MM/YYYY",
                    key="avanzado_fechas"
                )
            with col_fx2:
                est_seleccionados = st.multiselect(
                    "Establecimiento(s) (Vacío = Todos):",
                    options=lista_est_db,
                    key="avanzado_est"
                )

            col_fx3, col_fx4 = st.columns(2)
            with col_fx3:
                prof_seleccionados = st.multiselect(
                    "Profesional(es) (Vacío = Todos):",
                    options=lista_prof_db,
                    key="avanzado_prof"
                )
            with col_fx4:
                estados_seleccionados = st.multiselect(
                    "Estado(s) (Vacío = Todos):",
                    options=lista_estados_db,
                    key="avanzado_estado"
                )
            
            st.markdown("---")

            # Inicializamos las variables de fecha de forma segura
            f_inicio, f_fin = None, None

            if isinstance(rango_fechas_avanzado, tuple):
                if len(rango_fechas_avanzado) == 2:
                    f_inicio, f_fin = rango_fechas_avanzado
                elif len(rango_fechas_avanzado) == 1:
                    f_inicio = rango_fechas_avanzado[0]
                    f_fin = rango_fechas_avanzado[0]
            elif rango_fechas_avanzado is not None:
                f_inicio = rango_fechas_avanzado
                f_fin = rango_fechas_avanzado

            if f_inicio is not None and f_fin is not None:
                if f_inicio > f_fin:
                    f_inicio, f_fin = f_fin, f_inicio

                # Consulta SQL optimizada sin f.id y con filtros dinámicos
                conn_q = init_connection()
                cur_q = conn_q.cursor()
                try:
                    query = """
                        SELECT 
                            f.numero_fua,
                            COALESCE(e.nombre_establecimiento, 'Sin Establecimiento') AS establecimiento,
                            f.afiliado_dni,
                            f.afiliado_nombre,
                            f.afiliado_appaterno,
                            f.afiliado_apmaterno,
                            f.afiliado_fecha_nacimiento,
                            f.profesional_dni,
                            COALESCE(p.nombres_apellidos, 'Sin Profesional Asignado') AS profesional_nombre,
                            COALESCE(p.profesion_o_especialidad, 'N/A') AS profesional_especialidad,
                            f.digitador_dni,
                            f.tipo_observacion,
                            f.detalle_observacion,
                            f.fecha_atencion_fua,
                            f.estado,
                            f.fecha_registro,
                            f.fecha_correccion
                        FROM fuas_observadas f
                        LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
                        LEFT JOIN profesionales p ON TRIM(f.profesional_dni::text) = TRIM(p.dni::text)
                        WHERE f.fecha_registro::date >= %s AND f.fecha_registro::date <= %s
                    """
                    params = [f_inicio, f_fin]

                    if est_seleccionados:
                        query += " AND e.nombre_establecimiento = ANY(%s)"
                        params.append(est_seleccionados)

                    if prof_seleccionados:
                        query += " AND COALESCE(NULLIF(p.nombres_apellidos, ''), NULLIF(CONCAT('DNI: ', f.profesional_dni), 'DNI: '), 'Sin Profesional Asignado') = ANY(%s)"
                        params.append(prof_seleccionados)

                    if estados_seleccionados:
                        query += " AND f.estado = ANY(%s)"
                        params.append(estados_seleccionados)

                    query += " ORDER BY f.fecha_registro DESC;"

                    cur_q.execute(query, params)
                    datos_filtrados = cur_q.fetchall()
                except Exception as e:
                    st.error(f"Error en consulta: {e}")
                    datos_filtrados = []
                finally:
                    cur_q.close()
                    conn_q.close()

                if datos_filtrados:
                    df_filtrado = pd.DataFrame(
                        datos_filtrados, 
                        columns=[
                            "Nro FUA", "Establecimiento", "Afiliado DNI", 
                            "Afiliado Nombres", "Afiliado Ap. Paterno", "Afiliado Ap. Materno", 
                            "Afiliado F. Nacimiento", "Profesional DNI", "Profesional Nombre", 
                            "Profesional Especialidad", "Digitador DNI", "Tipo de Observación", 
                            "Detalle Observación", "Fecha Atención FUA", "Estado", 
                            "Fecha Registro", "Fecha Corrección"
                        ]
                    )
                    
                    st.markdown(f"**Registros encontrados:** `{len(df_filtrado)}`")
                    st.dataframe(df_filtrado, use_container_width=True)
                    
                    # --- BOTÓN DE EXPORTAR A EXCEL PARA ESTA PESTAÑA ---
                    import io
                    output_filtro = io.BytesIO()
                    with pd.ExcelWriter(output_filtro, engine='openpyxl') as writer:
                        df_filtrado.to_excel(writer, index=False, sheet_name='Reporte_Filtrado')
                    excel_bytes_filtro = output_filtro.getvalue()
                    
                    timestamp_filtro = datetime.now().strftime("%Y-%m-%d_%H-%M")
                    
                    st.download_button(
                        label="📥 Descargar Reporte Filtrado en Excel (.xlsx)",
                        data=excel_bytes_filtro,
                        file_name=f"reporte_filtrado_{timestamp_filtro}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        key="btn_download_filtro_excel",
                        use_container_width=True
                    )
                else:
                    st.info("ℹ️ No se encontraron registros para los filtros y rango de fechas seleccionados.")
            else:
                st.warning("⚠️ Por favor selecciona el rango completo de fechas para generar el reporte.")

    elif st.session_state.get("menu_activo") == "Backup":
        st.subheader("💾 Backup de la Base de Datos")
        st.markdown("---")
        
        # Pestañas internas para ordenar las acciones
        tab_gen, tab_rest = st.tabs(["📦 Generar Backup", "📥 Restaurar Backup"])
        
        # --- PESTAÑA 1: GENERAR BACKUP ---
        with tab_gen:
            st.markdown("### 🔄 Generar Backup (LOCAL)")
            st.write("Genera una copia de seguridad completa en formato `.sql`")
            
            if st.button("🚀 Crear y Descargar Backup"):
                # Verificar si pg_dump.exe realmente existe en esa ruta
                if not os.path.exists(PG_DUMP_PATH):
                    st.error(f"❌ No se encontró el archivo `pg_dump.exe` en la ruta: `{PG_DUMP_PATH}`. Por favor, verifica tu versión de PostgreSQL.")
                else:
                    try:
                        fecha_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"backup_fuas_{fecha_str}.sql"
                        filepath = os.path.join(os.getcwd(), filename)
                        
                        env_proceso = os.environ.copy()
                        env_proceso['PGPASSWORD'] = DB_PASSWORD
                        
                        cmd = [
                            PG_DUMP_PATH,
                            "-h", "localhost",
                            "-p", "5432",
                            "-U", DB_USER,
                            "-d", DB_NAME,
                            "-F", "p",
                            "-b",
                            "-v",
                            "-f", filepath
                        ]
                        
                        subprocess.run(cmd, env=env_proceso, check=True)
                        
                        if os.path.exists(filepath):
                            with open(filepath, "rb") as file:
                                st.download_button(
                                    label="⬇️ Descargar Archivo .sql",
                                    data=file,
                                    file_name=filename,
                                    mime="text/plain"
                                )
                            st.success("¡Backup generado con éxito!")
                        else:
                            st.error("No se pudo generar el archivo de respaldo.")
                            
                    except Exception as e:
                        st.error(f"Error al generar el backup: {e}")

             # --- SECCIÓN VISUAL EN LA INTERFAZ (Streamlit) ---
            st.markdown("### 🔄 Generar Backup (NUBE)")
            st.write("Genera una copia de seguridad completa en formato `.sql`")

            if st.button("📥 Generar y Descargar Backup (.sql)", type="secondary"):
                ruta_backup = generar_backup_bd()
                        
                if ruta_backup and os.path.exists(ruta_backup):
                     with open(ruta_backup, "rb") as f:
                        bytes_sql = f.read()
                                
                        nombre_descarga = os.path.basename(ruta_backup)
                        st.success("✅ ¡Respaldo generado con éxito!")
                            
                        # Botón de descarga directa en Streamlit
                        st.download_button(
                            label="⬇️ Hacer clic aquí para descargar el archivo .sql",
                            data=bytes_sql,
                            file_name=nombre_descarga,
                            mime="application/sql"
                        )

        # --- PESTAÑA 2: RESTAURAR BACKUP ---
        with tab_rest:
            st.markdown("### 🔄 Restauración de Base de Datos (local)")
            st.write("Sube un archivo de respaldo en formato `.sql`")
            
            archivo_subido = st.file_uploader("Selecciona tu archivo .sql", type=["sql"], key="uploader_restore")
            
            confirmar = st.checkbox("Confirmo que deseo sobrescribir la base de datos", key="chk_confirm_restore")
            
            if st.button("Ejecutar Restauración"):
                if not archivo_subido:
                    st.warning("⚠️ Por favor, selecciona un archivo .sql primero.")
                elif not confirmar:
                    st.warning("⚠️ Debes confirmar la casilla de advertencia antes de continuar.")
                else:
                    temp_sql_path = "temp_restore.sql"
                    try:
                        # 1. Guardar temporalmente el archivo subido
                        with open(temp_sql_path, "wb") as f:
                            f.write(archivo_subido.getbuffer())
                        
                        with st.spinner("Restaurando base de datos... Esto puede tomar unos segundos."):
                            import subprocess
                            import os
                            import glob
                            import psycopg2

                            # 2. Obtener credenciales de los secrets
                            pg_secrets = st.secrets["postgres"]
                            db_name = pg_secrets['database']
                            db_user = pg_secrets['user']
                            db_password = pg_secrets['password']
                            db_host = pg_secrets['host']
                            db_port = str(pg_secrets['port'])

                            # 3. Limpiar la base de datos actual antes de restaurar
                            conn_clean = psycopg2.connect(
                                dbname=db_name, user=db_user, password=db_password, host=db_host, port=db_port
                            )
                            conn_clean.autocommit = True
                            cursor_clean = conn_clean.cursor()
                            try:
                                cursor_clean.execute("DO $$ DECLARE r record; BEGIN FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE;'; END LOOP; END $$;")
                            except Exception as drop_err:
                                st.warning(f"Nota al limpiar tablas: {drop_err}")
                            cursor_clean.close()
                            conn_clean.close()

                            # 4. Buscar automáticamente la ruta de psql.exe en Windows
                            rutas_posibles = glob.glob(r"C:\Program Files\PostgreSQL\*\bin\psql.exe")
                            if rutas_posibles:
                                psql_exe = rutas_posibles[-1]  # Toma la versión más reciente instalada
                            else:
                                psql_exe = "psql"  # Intenta la variable global por si acaso

                            # 5. Configurar contraseña en entorno para psql
                            env = os.environ.copy()
                            env["PGPASSWORD"] = db_password

                            # 6. Ejecutar psql con el archivo .sql
                            cmd = [
                                psql_exe,
                                "-h", db_host,
                                "-p", db_port,
                                "-U", db_user,
                                "-d", db_name,
                                "-f", temp_sql_path
                            ]

                            resultado = subprocess.run(cmd, env=env, capture_output=True, text=True)

                            if resultado.returncode != 0 and "error" in resultado.stderr.lower():
                                raise Exception(f"Error en psql: {resultado.stderr}")

                        # 7. Limpiar archivo temporal
                        if os.path.exists(temp_sql_path):
                            os.remove(temp_sql_path)
                            
                        st.success("¡Base de datos restaurada exitosamente! Recargando sistema...")
                        st.rerun()

                    except Exception as e:
                        st.error(f"❌ Error crítico al restaurar: {e}")
                        if os.path.exists(temp_sql_path):
                            os.remove(temp_sql_path)
            
            # --- SECCIÓN VISUAL EN LA INTERFAZ (Streamlit) ---
            st.markdown("### 🔄 Restauración de Base de Datos (NUBE)")
            st.write("Sube un archivo de respaldo en formato `.sql`")

            archivo_subido = st.file_uploader("Seleccionar archivo de respaldo (.sql)", type=["sql"])

            if archivo_subido is not None:
                if st.button("🚀 Ejecutar Restauración Ahora", type="primary"):
                    # Guardamos el archivo subido en un archivo temporal de forma segura
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".sql") as tmp_file:
                        tmp_file.write(archivo_subido.getvalue())
                        tmp_path = tmp_file.name
                    
                    # Ejecutamos la función de restauración
                    restaurar_backup_bd(tmp_path)
                    
                    # Limpiamos el archivo temporal después de usarlo
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
    

    elif st.session_state.get("menu_activo") == "Afiliados":
        st.subheader("🪪 Gestión del Padrón de Afiliados")
        st.markdown("---")
        
        # Añadimos la pestaña de Exportar a las opciones existentes
        tab_lista, tab_exportar, tab_importar = st.tabs([
            "📋 Ver Lista", 
            "📥 Exportar a Excel", 
            "📤 Importar desde Excel / CSV"
        ])
        
        import psycopg2
        import io
        
        # --- PESTAÑA 1: VER LISTA ---
        with tab_lista:
            try:
                # Conexión dinámica compatible con Local y Nube (Supabase)
                conn = psycopg2.connect(
                    host=st.secrets["postgres"]["host"],
                    database=st.secrets["postgres"]["database"],
                    user=st.secrets["postgres"]["user"],
                    password=st.secrets["postgres"]["password"],
                    port=st.secrets["postgres"]["port"]
                )
                
                st.markdown("##### 🔍 Filtros de Búsqueda Avanzada")
                
                # Dividimos la sección de filtros en columnas para mayor orden
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    filtro_dni = st.text_input("DNI:", placeholder="Ej. 4755...")
                with col2:
                    filtro_appat = st.text_input("Apellido Paterno:", placeholder="Ej. Ramirez")
                with col3:
                    filtro_apmat = st.text_input("Apellido Materno:", placeholder="Ej. Holguino")
                with col4:
                    filtro_nombre = st.text_input("Nombre:", placeholder="Ej. Yola")
                
                # Construir la consulta SQL de manera dinámica según los campos llenados
                where_clauses = []
                
                if filtro_dni:
                    where_clauses.append(f"CAST(dni AS TEXT) ILIKE '%{filtro_dni.strip()}%'")
                if filtro_appat:
                    where_clauses.append(f"appaterno ILIKE '%{filtro_appat.strip()}%'")
                if filtro_apmat:
                    where_clauses.append(f"apmaterno ILIKE '%{filtro_apmat.strip()}%'")
                if filtro_nombre:
                    where_clauses.append(f"nombre ILIKE '%{filtro_nombre.strip()}%'")
                
                # Armar la cláusula WHERE si hay filtros activos
                condicion_sql = ""
                if where_clauses:
                    condicion_sql = "WHERE " + " AND ".join(where_clauses)
                
                query = f"""
                    SELECT 
                        numero AS "N°", 
                        establecimiento AS "Establecimiento", 
                        dni AS "DNI", 
                        nombre AS "Nombre", 
                        appaterno AS "Apellido Paterno", 
                        apmaterno AS "Apellido Materno", 
                        fecha_nacimiento AS "F. Nacimiento", 
                        direccion AS "Dirección"
                    FROM afiliados
                    {condicion_sql}
                    ORDER BY numero ASC
                    LIMIT 100;
                """
                
                df_afiliados = pd.read_sql(query, conn)
                conn.close()
                
                if where_clauses:
                    st.info(f"Mostrando resultados filtrados (máximo 100 en pantalla). Total histórico: **237,890**")
                else:
                    st.info(f"Mostrando los primeros 100 registros. Usa los filtros superiores para buscar a alguien específico. Total histórico: **237,890**")
                
                if not df_afiliados.empty:
                    st.dataframe(df_afiliados, use_container_width=True, hide_index=True)
                else:
                    st.warning("No se encontraron registros que coincidan con los filtros ingresados.")
                    
            except Exception as e:
                st.error(f"Error al cargar afiliados: {e}")

        # --- PESTAÑA 2: EXPORTAR A EXCEL ---
        with tab_exportar:
            st.write("Descarga una copia completa o filtrada de todos los afiliados registrados en la base de datos en formato Excel (`.xlsx`).")
            
            # Opciones de exportación
            tipo_exportacion = st.radio(
                "Selecciona el alcance de la exportación:",
                ["Exportar TODOS los registros (237,890+)", "Exportar solo por Establecimiento específico"]
            )
            
            establecimiento_filtro = ""
            if "Establecimiento específico" in tipo_exportacion:
                est_input = st.text_input("Ingresa el nombre del establecimiento (ej. C.S. YAURI):")
                if est_input:
                    establecimiento_filtro = est_input.strip()

            if st.button("📊 Generar Archivo Excel para Descarga"):
                try:
                    with st.spinner("Consultando la base de datos y generando el Excel... Esto puede tomar unos segundos."):
                        
                        # Conexión dinámica: Usa st.secrets si existe (Nube), o variables locales si no
                        if "postgres" in st.secrets:
                            pg_config = st.secrets["postgres"]
                            # Detecta automáticamente si usaste 'dbname' o 'database'
                            db_name = pg_config.get("dbname") or pg_config.get("database")
                            
                            conn = psycopg2.connect(
                                host=pg_config["host"],
                                database=db_name,
                                user=pg_config["user"],
                                password=pg_config["password"],
                                port=pg_config["port"]
                            )
                        else:
                            conn = psycopg2.connect(
                                host="localhost",
                                database=DB_NAME,
                                user=DB_USER,
                                password=DB_PASSWORD,
                                port="5432"
                            )
                        
                        # Consulta segura usando parámetros en lugar de f-strings
                        if establecimiento_filtro:
                            query_exp = """
                                SELECT numero, establecimiento, dni, nombre, appaterno, apmaterno, fecha_nacimiento, direccion
                                FROM afiliados
                                WHERE establecimiento ILIKE %s
                                ORDER BY numero ASC;
                            """
                            params = (f"%{establecimiento_filtro}%",)
                            df_export = pd.read_sql(query_exp, conn, params=params)
                        else:
                            query_exp = """
                                SELECT numero, establecimiento, dni, nombre, appaterno, apmaterno, fecha_nacimiento, direccion
                                FROM afiliados
                                ORDER BY numero ASC;
                            """
                            df_export = pd.read_sql(query_exp, conn)
                        
                        conn.close()
                        
                        if not df_export.empty:
                            # Crear el archivo Excel en memoria usando BytesIO
                            output = io.BytesIO()
                            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                                df_export.to_excel(writer, index=False, sheet_name='Afiliados')
                            processed_data = output.getvalue()
                            
                            st.success(f"¡Se han preparado **{len(df_export):,}** registros con éxito!")
                            
                            st.download_button(
                                label="📥 Descargar Excel de Afiliados",
                                data=processed_data,
                                file_name="padron_afiliados_fua.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                        else:
                            st.warning("No se encontraron registros para exportar con los filtros seleccionados.")
                            
                except Exception as e:
                    st.error(f"Error al generar la exportación: {e}")

        # --- PESTAÑA 3: IMPORTAR DESDE EXCEL ---
        with tab_importar:
            st.warning("⚠️ **Aviso:** La importación procesará el archivo Excel y actualizará los registros en la base de datos.")
            
            archivo_subido = st.file_uploader("Sube tu archivo en formato Excel (.xlsx) o CSV", type=["xlsx", "csv"])
            
            modo_carga = st.radio(
                "Selecciona el modo de actualización:",
                ["Añadir / Actualizar registros", "⚠️ REEMPLAZAR TODO (Borra la tabla actual e ingresa los nuevos)"]
            )
            
            if archivo_subido is not None:
                if st.button("🚀 Procesar e Importar Datos"):
                    try:
                        with st.spinner("Leyendo archivo y actualizando la base de datos... Por favor espera."):
                            if archivo_subido.name.endswith('.xlsx'):
                                df_nuevo = pd.read_excel(archivo_subido)
                            else:
                                df_nuevo = pd.read_csv(archivo_subido)
                            
                            df_nuevo.columns = [col.strip().lower() for col in df_nuevo.columns]
                            
                            from sqlalchemy import create_engine
                            engine = create_engine(f'postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@localhost:5432/{DB_NAME}')
                            
                            if "REEMPLAZAR TODO" in modo_carga:
                                df_nuevo.to_sql('afiliados', engine, if_exists='replace', index=False)
                                st.success(f"¡Tabla reemplazada con éxito! Se importaron {len(df_nuevo)} registros.")
                            else:
                                df_nuevo.to_sql('afiliados', engine, if_exists='append', index=False)
                                st.success(f"¡Se agregaron {len(df_nuevo)} registros correctamente a la base de datos!")
                                
                    except Exception as e:
                        st.error(f"Error durante la importación masiva: {e}")

    if st.session_state.get("menu_activo") == "Cargar ARFSIS-Web":
        st.title("📤 Cargar Base de FUAs Digitadas (ARFSIS-Web)")
        st.caption("Carga el archivo Excel descargado del sistema del MINSA para acumular los registros en la base de datos.")

        archivo_excel = st.file_uploader(
            "Seleccione el archivo Excel (.xlsx, .xls)",
            type=["xlsx", "xls"],
            key="uploader_arfsis",
        )

        if archivo_excel is not None:
            try:
                # Leer el Excel únicamente al seleccionar el archivo
                df_arfsis = pd.read_excel(archivo_excel)

                st.success(f"📂 Archivo leído correctamente con {len(df_arfsis)} filas.")
                st.dataframe(df_arfsis.head(5), use_container_width=True)

                if st.button("🚀 Agregar a PostgreSQL", type="primary", use_container_width=True):
                    with st.spinner("Verificando duplicados y añadiendo registros nuevos a 'digitados_arfsis'..."):
                        db_host = st.secrets["postgres"]["host"]
                        db_port = st.secrets["postgres"]["port"]
                        db_name = st.secrets["postgres"]["database"]
                        db_user = st.secrets["postgres"]["user"]
                        db_pass = st.secrets["postgres"]["password"]

                        ENGINE_URL = f"postgresql+psycopg2://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
                        engine = create_engine(ENGINE_URL)

                        # Convertir columnas de fecha si existen en el Excel
                        if "fecha_nacimiento" in df_arfsis.columns:
                            df_arfsis["fecha_nacimiento"] = pd.to_datetime(
                                df_arfsis["fecha_nacimiento"], dayfirst=True, errors="coerce"
                            )
                        if "fecha_registro" in df_arfsis.columns:
                            df_arfsis["fecha_registro"] = pd.to_datetime(
                                df_arfsis["fecha_registro"], dayfirst=True, errors="coerce"
                            )

                        # 1. Eliminar duplicados dentro del propio archivo Excel subido
                        if "numero_fua" in df_arfsis.columns:
                            df_arfsis["numero_fua"] = df_arfsis["numero_fua"].astype(str).str.strip()
                            df_arfsis = df_arfsis.drop_duplicates(subset=["numero_fua"])

                            # 2. Consultar FUAs que ya existen en la base de datos
                            df_existentes = pd.read_sql("SELECT numero_fua FROM digitados_arfsis", con=engine)

                            if not df_existentes.empty:
                                df_existentes["numero_fua"] = df_existentes["numero_fua"].astype(str).str.strip()
                                # Filtrar solo las FUAs que NO estén en la base de datos
                                df_nuevos = df_arfsis[~df_arfsis["numero_fua"].isin(df_existentes["numero_fua"])]
                            else:
                                df_nuevos = df_arfsis.copy()
                        else:
                            df_nuevos = df_arfsis.copy()

                        # 3. Guardar en la base de datos solo si hay filas nuevas
                        if not df_nuevos.empty:
                            df_nuevos.to_sql(
                                name="digitados_arfsis",
                                con=engine,
                                if_exists="append",
                                index=False,
                            )
                            st.success(
                                f"✅ ¡Éxito! Se agregaron {len(df_nuevos)} nuevos registros a la base de datos. "
                                f"(Se ignoraron {len(df_arfsis) - len(df_nuevos)} registros que ya existían)."
                            )
                        else:
                            st.info("ℹ️ No hay registros nuevos para agregar. Todos los FUAs de este archivo ya se encuentran registrados.")

                        st.markdown("---")
                        st.subheader(
                            "📊 Registros Almacenados en la Base de Datos"
                        )

                        df_bd = pd.read_sql(
                            "SELECT * FROM digitados_arfsis ORDER BY 1 DESC",
                            con=engine,
                        )

                        if not df_bd.empty:
                          st.info(
                              "📌 **Total de registros guardados en la BD:**"
                              f" {len(df_bd)} filas"
                          )
                          st.dataframe(
                              df_bd, use_container_width=True, height=400
                          )
                        else:
                          st.warning(
                              "⚠️ Aún no hay registros guardados en la tabla"
                              " 'digitados_arfsis'."
                          )

                        st.markdown("---")
                        st.subheader("📊 Registros Almacenados en la Base de Datos")

                        try:
                            query = "SELECT * FROM digitados_arfsis ORDER BY fecha_registro DESC"
                            df_bd = pd.read_sql(query, con=engine)

                            if not df_bd.empty:
                                st.info(
                                    f"📌 **Total de registros guardados en la BD:** {len(df_bd)} filas"
                            )
                                st.dataframe(df_bd, use_container_width=True, height=400)
                            else:
                                st.warning(
                                "⚠️ La tabla 'digitados_arfsis' está conectada, pero no tiene"
                                " registros."
                            )

                        except Exception as db_err:
                            st.error(f"❌ Error crítico en la BD: {db_err}")

            except Exception as err:
                st.error(f"Error al procesar el archivo: {err}")

    if st.session_state.get("menu_activo") == "Sincronizacion ARFSIS-Web":
        st.title("📊 Bandeja de Control y Conciliación de FUAs")
        st.markdown("Cruza automáticamente las FUAs observadas con el reporte oficial de ARFSIS-Web del MINSA.")

        try:
            # 1. Conexión a la base de datos usando st.secrets
            db_host = st.secrets["postgres"]["host"]
            db_port = st.secrets["postgres"]["port"]
            db_name = st.secrets["postgres"]["database"]
            db_user = st.secrets["postgres"]["user"]
            db_pass = st.secrets["postgres"]["password"]

            ENGINE_URL = f"postgresql+psycopg2://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
            engine = create_engine(ENGINE_URL)

            # 2. Consulta SQL optimizada para evitar duplicados por cruces con ARFSIS
            query_conciliacion = """
                WITH arfsis_limpio AS (
                    -- Aseguramos que cada número de FUA aparezca una sola vez (tomando el más reciente o el primero)
                    SELECT DISTINCT ON (TRIM(numero_fua::text)) 
                        numero_fua, 
                        digitador, 
                        fecha_registro
                    FROM digitados_arfsis
                    ORDER BY TRIM(numero_fua::text), fecha_registro DESC
                )
                SELECT 
                    f.id,
                    f.numero_fua AS "Nº FUA",
                    COALESCE(e.nombre_establecimiento, f.establecimiento_id::text, '-') AS "Establecimiento",
                    f.afiliado_dni AS "DNI Paciente",
                    TRIM(CONCAT(f.afiliado_nombre, ' ', f.afiliado_appaterno, ' ', f.afiliado_apmaterno)) AS "Paciente",
                    f.estado AS "Estado Local",
                    
                    -- Estado en ARFSIS
                    CASE 
                        WHEN f.estado = 'Anulado' THEN 'Anulado'
                        WHEN a.numero_fua IS NOT NULL THEN 'Digitado'
                        ELSE 'Pendiente de Digitación'
                    END AS "Estado en ARFSIS",
                    
                    -- Nombre del Digitador
                    COALESCE(
                        CASE WHEN f.estado = 'Anulado' THEN ul.nombre_completo END,
                        u.nombre_completo, 
                        a.digitador::text, 
                        '-'
                    ) AS "Digitador",
                    
                    -- Fecha de registro/corrección
                    COALESCE(
                        CASE WHEN f.estado = 'Anulado' THEN TO_CHAR(f.fecha_correccion, 'DD/MM/YYYY') END,
                        TO_CHAR(a.fecha_registro, 'DD/MM/YYYY'), 
                        '-'
                    ) AS "Fecha Digitación MINSA"

                FROM fuas_observadas f
                LEFT JOIN establecimientos e 
                    ON f.establecimiento_id = e.id
                LEFT JOIN arfsis_limpio a 
                    ON TRIM(f.numero_fua::text) = TRIM(a.numero_fua::text)
                LEFT JOIN usuarios u 
                    ON TRIM(a.digitador::text) = TRIM(u.dni::text)
                LEFT JOIN usuarios ul 
                    ON TRIM(f.digitador_dni::text) = TRIM(ul.dni::text)
                ORDER BY f.id DESC;
            """

            df_bandeja = pd.read_sql(query_conciliacion, con=engine)

            if not df_bandeja.empty:
                # 3. Métricas rápidas (KPIs) con diseño flexible y adaptativo
                total_fuas = len(df_bandeja)
                digitadas = len(df_bandeja[df_bandeja["Estado en ARFSIS"] == "Digitado"])
                pendientes = len(df_bandeja[df_bandeja["Estado en ARFSIS"] == "Pendiente de Digitación"])
                anuladas = len(df_bandeja[df_bandeja["Estado en ARFSIS"] == "Anulado"])

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.markdown(f"""
                        <div style="background-color: #0e1117; padding: 12px; border-radius: 8px; border: 1px solid #262730; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                            <div>
                                <p style="color: #a3a8b8; font-size: 12px; margin-bottom: 2px;">Total Observadas</p>
                                <h2 style="color: white; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{total_fuas}</h2>
                            </div>
                            <div>
                                <span style="background-color: #1a2332; color: #4fa3ff; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                                    Total
                                </span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                with col2:
                    st.markdown(f"""
                        <div style="background-color: #0e1117; padding: 12px; border-radius: 8px; border: 1px solid #262730; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                            <div>
                                <p style="color: #a3a8b8; font-size: 12px; margin-bottom: 2px;">Ya Digitadas (MINSA)</p>
                                <h2 style="color: white; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{digitadas}</h2>
                            </div>
                            <div>
                                <span style="background-color: #113322; color: #00cc66; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                                    ↑ {digitadas}
                                </span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown(f"""
                        <div style="background-color: #0e1117; padding: 12px; border-radius: 8px; border: 1px solid #262730; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                            <div>
                                <p style="color: #a3a8b8; font-size: 12px; margin-bottom: 2px;">Pendientes</p>
                                <h2 style="color: white; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{pendientes}</h2>
                            </div>
                            <div>
                                <span style="background-color: #332b00; color: #ffcc00; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                                    ↓ -{pendientes}
                                </span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                with col4:
                    st.markdown(f"""
                        <div style="background-color: #0e1117; padding: 12px; border-radius: 8px; border: 1px solid #262730; display: flex; flex-direction: column; justify-content: space-between; min-height: 115px;">
                            <div>
                                <p style="color: #a3a8b8; font-size: 12px; margin-bottom: 2px;">Anuladas</p>
                                <h2 style="color: white; margin-top: 0px; margin-bottom: 4px; font-size: 22px;">{anuladas}</h2>
                            </div>
                            <div>
                                <span style="background-color: #331111; color: #ff4444; padding: 2px 6px; border-radius: 10px; font-size: 10px; font-weight: bold; display: inline-block;">
                                    ↓ {anuladas}
                                </span>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")

                # 4. Filtros interactivos en 3 columnas
                col_f1, col_f2, col_f3 = st.columns(3)

                with col_f1:
                    filtro_estado = st.selectbox(
                        "Filtrar por Estado:",
                        ["Todas", "Pendientes", "Digitadas", "Anulados"]
                    )

                with col_f2:
                    lista_eess = ["Todos"] + sorted(list(df_bandeja["Establecimiento"].unique()))
                    filtro_eess = st.selectbox(
                        "Filtrar por Establecimiento:",
                        lista_eess
                    )

                with col_f3:
                    lista_digitadores = ["Todos"] + sorted(list(df_bandeja["Digitador"].unique()))
                    filtro_digitador = st.selectbox(
                        "Filtrar por Digitador:",
                        lista_digitadores
                    )

                # Aplicar la lógica de filtrado acumulativo
                df_filtrado = df_bandeja.copy()

                if filtro_estado == "Pendientes":
                    df_filtrado = df_filtrado[df_filtrado["Estado en ARFSIS"] == "Pendiente de Digitación"]
                elif filtro_estado == "Digitadas":
                    df_filtrado = df_filtrado[df_filtrado["Estado en ARFSIS"] == "Digitado"]
                elif filtro_estado == "Anulados":
                    df_filtrado = df_filtrado[df_filtrado["Estado Local"] == "Anulado"]

                if filtro_eess != "Todos":
                    df_filtrado = df_filtrado[df_filtrado["Establecimiento"] == filtro_eess]

                if filtro_digitador != "Todos":
                    df_filtrado = df_filtrado[df_filtrado["Digitador"] == filtro_digitador]

                # 5. Función de formato condicional con los colores requeridos
                def estilizar_estado(val):
                    val_str = str(val)
                    if "Pendiente" in val_str:
                        return "color: #D4AC0D; font-weight: bold;"  # Amarillo
                    elif "Anulado" in val_str:
                        return "color: #E74C3C; font-weight: bold;"  # Rojo
                    elif val in ["Corregido", "Digitado"]:
                        return "color: #2ECC71; font-weight: bold;"  # Verde
                    return ""

                df_estilizado = df_filtrado.style.map(
                    estilizar_estado, 
                    subset=["Estado Local", "Estado en ARFSIS"]
                )

                # 6. Renderizar tabla en Streamlit
                st.dataframe(df_estilizado, use_container_width=True, hide_index=True)

            else:
                st.info("No se encontraron registros en la tabla 'fuas_observadas'.")

        except Exception as err:
            st.error(f"Error al conectar con la base de datos o realizar la conciliación: {err}")


    elif st.session_state.get("menu_activo") == "Entregar Cargo":
        st.title("📦 Entrega y Generación de Cargos de FUAs")
        st.caption("Genera el cargo impreso y registra el historial de entrega de FUAs observadas por profesional y establecimiento.")

        pestana_nuevo, pestana_historial = st.tabs(["📦 Nuevo Cargo", "📋 Historial y Consulta"])

        # ==========================================
        # PESTAÑA 1: NUEVO CARGO
        # ==========================================
        with pestana_nuevo:
            st.markdown("### 📋 Generación de Nuevo Cargo")
            
            try:
                conn_nuevo = init_connection()
                # Consulta incluyendo el nombre del establecimiento y el digitador (usuario_registro)
                query_pendientes = """
                    SELECT 
                        f.id AS "ID",
                        f.numero_fua AS "Nº FUA",
                        f.id_prestacion AS "ID Prestación",
                        COALESCE(p.nombres_apellidos, f.profesional_dni) AS "Profesional",
                        f.tipo_observacion AS "Tipo Observación",
                        f.fecha_atencion_fua AS "Fecha Atención",
                        f.fecha_registro AS "Fecha Registro",
                        COALESCE(e.nombre_establecimiento, f.establecimiento_id::text) AS "Establecimiento",
                        COALESCE(u.nombre_completo, f.digitador_dni, 'NO ASIGNADO') AS "Digitador",
                        f.cargo_id
                    FROM fuas_observadas f
                    LEFT JOIN profesionales p ON TRIM(f.profesional_dni) = TRIM(p.dni)
                    LEFT JOIN establecimientos e ON f.establecimiento_id = e.id
                    LEFT JOIN usuarios u ON TRIM(f.digitador_dni) = TRIM(u.dni)
                """
            
                df_fuas = pd.read_sql(query_pendientes, conn_nuevo)
                conn_nuevo.close()
            except Exception as e:
                st.error(f"Error al conectar con la base de datos: {e}")
                df_fuas = pd.DataFrame()

            if df_fuas.empty:
                st.warning("⚠️ No hay registros en la base de datos.")
            else:
                # 📊 Cálculo de métricas totales
                total_general = len(df_fuas)
                total_pendientes = len(df_fuas[df_fuas["cargo_id"].isna() | (df_fuas["cargo_id"] == 0)])
                total_con_cargo = total_general - total_pendientes

                # Mostrar tarjetas de métricas en pantalla
                col_m1, col_m2, col_m3 = st.columns(3)
                col_m1.metric("📊 Total de Registros", total_general)
                col_m2.metric("⏳ Pendientes (Sin Cargo)", total_pendientes)
                col_m3.metric("📄 Con Cargo Asignado", total_con_cargo)
                
                st.markdown("---")

                # --- FILTROS DE CABECERA (4 Columnas: Profesional, Establecimiento, Digitador, Fechas) ---
                col_f1, col_f2, col_f3, col_f4 = st.columns([2, 2, 2, 2])
                
                with col_f1:
                    profesionales_disponibles = ["Todos"] + sorted(df_fuas["Profesional"].dropna().astype(str).unique().tolist()) if "Profesional" in df_fuas.columns else ["Todos"]
                    profesional_seleccionado = st.selectbox("Seleccionar Profesional Responsable", options=profesionales_disponibles, key="sel_prof_nuevo")

                with col_f2:
                    establecimientos_disponibles = ["Todos"] + sorted(df_fuas["Establecimiento"].dropna().astype(str).unique().tolist()) if "Establecimiento" in df_fuas.columns else ["Todos"]
                    establecimiento_seleccionado = st.selectbox("Establecimiento", options=establecimientos_disponibles, key="sel_est_nuevo")

                with col_f3:
                    digitadores_disponibles = ["Todos"] + sorted(df_fuas["Digitador"].dropna().astype(str).unique().tolist()) if "Digitador" in df_fuas.columns else ["Todos"]
                    digitador_seleccionado = st.selectbox("Digitador", options=digitadores_disponibles, key="sel_dig_nuevo")

                with col_f4:
                    # 📌 FILTRO POR RANGO DE FECHA DE REGISTRO
                    df_fuas["Fecha_Reg_Solo"] = pd.to_datetime(df_fuas["Fecha Registro"], errors='coerce').dt.date
                    min_fecha = df_fuas["Fecha_Reg_Solo"].min()
                    max_fecha = df_fuas["Fecha_Reg_Solo"].max()
                    
                    if pd.notna(min_fecha) and pd.notna(max_fecha):
                        rango_fechas_cargo = st.date_input(
                            "Filtrar por Rango de Fecha de Registro",
                            value=(min_fecha, max_fecha),
                            format="DD/MM/YYYY",
                            key="rango_fecha_nuevo"
                        )
                    else:
                        rango_fechas_cargo = None

                # --- APLICAR FILTROS ---
                df_bloque = df_fuas.copy()

                if profesional_seleccionado != "Todos":
                    df_bloque = df_bloque[df_bloque["Profesional"] == profesional_seleccionado]

                if establecimiento_seleccionado != "Todos":
                    df_bloque = df_bloque[df_bloque["Establecimiento"] == establecimiento_seleccionado]

                if digitador_seleccionado != "Todos":
                    df_bloque = df_bloque[df_bloque["Digitador"] == digitador_seleccionado]

                if rango_fechas_cargo and isinstance(rango_fechas_cargo, tuple) and len(rango_fechas_cargo) == 2:
                    f_ini, f_fin = rango_fechas_cargo
                    df_bloque = df_bloque[
                        (df_bloque["Fecha_Reg_Solo"] >= f_ini) & 
                        (df_bloque["Fecha_Reg_Solo"] <= f_fin)
                    ]

                # --- MOSTRAR RESULTADOS ---
                st.info(f"📋 Mostrando **{len(df_bloque)}** registros filtrados.")
                
                cols_deseadas = ["ID", "Nº FUA", "ID Prestación", "Profesional", "Tipo Observación", "Fecha Atención", "Digitador"]
                
                for col in cols_deseadas:
                    if col not in df_bloque.columns:
                        df_bloque[col] = "-"

                st.dataframe(df_bloque[cols_deseadas], use_container_width=True, hide_index=True)
                
                # 📌 Campo para el DNI del profesional que recibe el bloque
                dni_prof = st.text_input("DNI del Profesional que Recibe el Bloque (Opcional)", max_chars=8, key="input_dni_nuevo")
                
                nombre_encontrado = ""
                if dni_prof.strip():
                    try:
                        conn_temp = init_connection()
                        query_p = f"SELECT nombres_apellidos FROM profesionales WHERE TRIM(dni) = '{dni_prof.strip()}'"
                        df_p = pd.read_sql(query_p, conn_temp)
                        conn_temp.close()
                        
                        if not df_p.empty and df_p.iloc[0]["nombres_apellidos"]:
                            nombre_encontrado = str(df_p.iloc[0]["nombres_apellidos"]).strip().upper()
                    except Exception as e:
                        st.error(f"Error en consulta: {e}")
                    
                    if nombre_encontrado:
                        partes = nombre_encontrado.split()
                        if len(partes) >= 4:
                            nombres_ordenados = f"{partes[-2]} {partes[-1]} {partes[0]} {partes[1]}"
                        else:
                            nombres_ordenados = nombre_encontrado

                        st.success(f"👤 **Profesional Encontrado:** {nombres_ordenados}")
                        profesional_recibe_str = nombres_ordenados
                    else:
                        st.warning(f"⚠️ DNI {dni_prof.strip()} ingresado como referencia para la firma.")
                        profesional_recibe_str = f"PROFESIONAL (DNI: {dni_prof.strip()})"
                else:
                    profesional_recibe_str = profesional_seleccionado if profesional_seleccionado != "Todos" else "Varios / Representante"

                if st.button("🚀 Generar Cargo", type="primary", key="btn_generar_cargo_nuevo"):
                    if len(df_bloque) == 0:
                        st.warning("No hay FUAs en este filtro para entregar.")
                    else:
                        user_info = st.session_state.get("user", {})
                        usuario_actual = (
                            user_info.get("nombre_completo") or 
                            st.session_state.get("nombre_completo") or 
                            user_info.get("nombre") or 
                            user_info.get("nombres") or 
                            "PERSONAL DE DIGITACIÓN"
                        )
                        usuario_actual = str(usuario_actual).strip().upper()
                        
                        cargo_id, codigo_cargo = registrar_cargo_entrega(
                            df_bloque, 
                            profesional_recibe_str, 
                            dni_prof, 
                            establecimiento_seleccionado if establecimiento_seleccionado != "Todos" else "Varios", 
                            usuario_actual
                        )
                        
                        if cargo_id and codigo_cargo:
                            st.success(f"¡Cargo **{codigo_cargo}** generado exitosamente!")
                            
                            html_cargo = generar_html_cargo(
                                codigo_cargo, 
                                profesional_recibe_str, 
                                establecimiento_seleccionado, 
                                df_bloque, 
                                usuario_actual
                            )
                            st.components.v1.html(html_cargo, height=600, scrolling=True)

        # ==========================================
        # PESTAÑA 2: HISTORIAL Y CONSULTA
        # ==========================================
        with pestana_historial:
            st.markdown("### 🔍 Consultar Cargos Anteriores")
            
            try:
                conn_hist = init_connection()
                df_cargos = pd.read_sql("SELECT * FROM cargos_entrega ORDER BY id DESC", conn_hist)
                conn_hist.close()
                
                if df_cargos.empty:
                    st.info("No hay cargos registrados todavía.")
                else:
                    col_h1, col_h2 = st.columns(2)
                    with col_h1:
                        filtro_codigo = st.text_input("🔍 Buscar por Código de Cargo", key="f_cod_hist")
                    with col_h2:
                        filtro_profesional = st.text_input("🔍 Buscar por Profesional o DNI", key="f_prof_hist")
                        
                    df_filtrado = df_cargos.copy()
                    if filtro_codigo.strip() and 'codigo_cargo' in df_filtrado.columns:
                        df_filtrado = df_filtrado[df_filtrado['codigo_cargo'].astype(str).str.contains(filtro_codigo.strip(), case=False, na=False)]
                    
                    if filtro_profesional.strip():
                        mask = df_filtrado['profesional_responsable'].astype(str).str.contains(filtro_profesional.strip(), case=False, na=False)
                        if 'dni_profesional' in df_filtrado.columns:
                            mask = mask | df_filtrado['dni_profesional'].astype(str).str.contains(filtro_profesional.strip(), case=False, na=False)
                        df_filtrado = df_filtrado[mask]
                        
                    st.dataframe(df_filtrado, use_container_width=True, hide_index=True)
                    
                    st.markdown("---")
                    st.markdown("### 🖨️ Re-imprimir Cargo del Historial")
                    
                    lista_codigos = df_filtrado['codigo_cargo'].tolist() if not df_filtrado.empty else []
                    if lista_codigos:
                        cargo_seleccionado = st.selectbox("Seleccione el Código de Cargo a Visualizar:", lista_codigos, key="sel_cargo_reprint")
                        
                        if st.button("📄 Cargar y Ver Documento", key="btn_ver_reprint"):
                            info_cargo = df_cargos[df_cargos['codigo_cargo'] == cargo_seleccionado].iloc[0]
                            cargo_pk_id = info_cargo['id']
                            val_prof_cargo = str(info_cargo.get('profesional_responsable', '')).strip()
                            
                            conn_det = init_connection()
                            
                            # 1. Búsqueda por relación directa (cargo_id) trayendo el Nombre Completo del Profesional
                            query_detalle = f"""
                                SELECT 
                                    f.numero_fua AS "Nº FUA", 
                                    COALESCE(p.nombres_apellidos, f.profesional_dni) AS "Profesional", 
                                    f.tipo_observacion AS "Tipo Observación", 
                                    f.fecha_atencion_fua AS "Fecha Atención"
                                FROM fuas_observadas f
                                LEFT JOIN profesionales p ON TRIM(f.profesional_dni) = TRIM(p.dni)
                                WHERE f.cargo_id = {cargo_pk_id} OR f.cargo_id::text = '{cargo_seleccionado}'
                            """
                            df_detalle = pd.read_sql(query_detalle, conn_det)
                            
                            # 2. Respaldo por DNI si es un cargo previo
                            if df_detalle.empty and val_prof_cargo:
                                query_dni = f"""
                                    SELECT dni FROM profesionales 
                                    WHERE nombres_apellidos ILIKE '%{val_prof_cargo}%'
                                    LIMIT 1
                                """
                                df_dni_res = pd.read_sql(query_dni, conn_det)
                                
                                if not df_dni_res.empty:
                                    dni_encontrado = str(df_dni_res.iloc[0]["dni"]).strip()
                                    query_respaldo = f"""
                                        SELECT 
                                            f.numero_fua AS "Nº FUA", 
                                            COALESCE(p.nombres_apellidos, f.profesional_dni) AS "Profesional", 
                                            f.tipo_observacion AS "Tipo Observación", 
                                            f.fecha_atencion_fua AS "Fecha Atención"
                                        FROM fuas_observadas f
                                        LEFT JOIN profesionales p ON TRIM(f.profesional_dni) = TRIM(p.dni)
                                        WHERE TRIM(f.profesional_dni) = '{dni_encontrado}' AND (f.cargo_id IS NULL OR f.cargo_id = 0)
                                    """
                                    df_detalle = pd.read_sql(query_respaldo, conn_det)
                                    
                            conn_det.close()
                            
                            # Aviso si el registro histórico no posee ítems vinculados
                            if df_detalle.empty:
                                st.warning("⚠️ Este es un cargo histórico o de prueba anterior; no cuenta con FUAs asociadas en la base de datos.")
                            
                            val_prof = str(info_cargo.get('profesional_responsable', 'PROFESIONAL'))
                            val_est = str(info_cargo.get('establecimiento', 'Varios'))
                            val_user = str(info_cargo.get('usuario_registro', 'PERSONAL DE DIGITACIÓN'))
                            
                            html_reimpresion = generar_html_cargo(
                                cargo_seleccionado,
                                val_prof,
                                val_est,
                                df_detalle,
                                val_user
                            )
                            
                            st.components.v1.html(html_reimpresion, height=600, scrolling=True)
                            
            except Exception as e:
                st.error(f"Error al consultar el historial de cargos: {e}")