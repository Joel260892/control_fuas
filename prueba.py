import libsql

# Tus credenciales generadas en Turso
TURSO_URL = "libsql://bdfuas-joel1992.aws-sa-east-1.turso.io"
TURSO_AUTH_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTI1ODY5OTAsImlkIjoiMDFhMTVlN2YtYjgwMS03M2E0LTgzMDgtYzI3NzcyNTA1ZWIwIiwia2lkIjoiR2dXUGVFR1FzTzhUNTdkaHZ4bmcyNXYxcm9ldXA0TC1WRFpFQ3hPb1VYayIsInJpZCI6ImM4NTQ4M2JjLTk1ZWItNDhjNy1iZjYxLTlhZWU3ZWNmMjJhMSJ9.vAQb26A8m1julm-Vjm9DqnFa4x3xwR8ezSZEeC_id1wf3hoAi7gx8efTMoxuauy40sl31bTKyfMUDNvxUXEiAg"

print("Conectando a Turso...")

try:
    conn = libsql.connect(database=TURSO_URL, auth_token=TURSO_AUTH_TOKEN)
    cursor = conn.cursor()
    
    # Consulta de prueba
    cursor.execute("SELECT 1;")
    result = cursor.fetchone()
    
    print("¡CONEXIÓN EXITOSA A TURSO!")
    print(f"Respuesta del servidor: {result}")

    cursor.close()
    conn.close()

except Exception as e:
    print("Ocurrió un error al conectar:")
    print(e)