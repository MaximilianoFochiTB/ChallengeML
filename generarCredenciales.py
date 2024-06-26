from cryptography.fernet import Fernet
import json

# Generar una clave para la encriptación
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Credenciales de la base de datos
db_uri = 'postgresql://localhost:5432/vulnerabilidades_db'
db_uri_flask = 'localhost:5432/vulnerabilidades_db'
db_user = 'postgres'
db_password = 'postgres'
#Se utilizan credenciales por defecto en este archivo al estar en un entorno DEV, y así facilitar la puesta en marcha. Para migrar a productivo se deben cambiar necesariamente las credenciales por defecto. 

# Encriptar las credenciales
encrypted_db_uri = cipher_suite.encrypt(db_uri.encode('utf-8')).decode('utf-8')
encrypted_db_uri_flask = cipher_suite.encrypt(db_uri_flask.encode('utf-8')).decode('utf-8')
encrypted_db_user = cipher_suite.encrypt(db_user.encode('utf-8')).decode('utf-8')
encrypted_db_password = cipher_suite.encrypt(db_password.encode('utf-8')).decode('utf-8')

# Guardar las credenciales encriptadas en un archivo JSON
config_data = {
    "db_uri": encrypted_db_uri,
    "db_uri_flask": encrypted_db_uri_flask,
    "db_user": encrypted_db_user,
    "db_password": encrypted_db_password
}

with open('config.json', 'w') as config_file:
    json.dump(config_data, config_file, indent=4)

# Guardar la clave de encriptación en un archivo
with open('key.key', 'wb') as key_file:
    key_file.write(key)

print("Archivos 'config.json' y 'key.key' generados exitosamente.")
