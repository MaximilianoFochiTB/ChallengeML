# ChallengeML
Requisitos Previos
Python 3.8 o superior
PostgreSQL instalado y configurado
Instalar pip para la gestión de paquetes de Python

Paso 1: Configurar PostgreSQL
Crear la base de datos:
sql
Copiar código
CREATE DATABASE vulnerabilidades_db;

Crear un usuario y asignarle permisos:
sql
Copiar código
CREATE USER usuario WITH PASSWORD 'contraseña';
GRANT ALL PRIVILEGES ON DATABASE vulnerabilidades_db TO usuario;

LEVANTAR EL BACKUP DE LA BASE vulnerabilidades_db

Paso 2: Configurar el Proyecto
Crear un entorno virtual:


Copiar código
python -m venv venv

Activar el entorno virtual:

En Windows:

Copiar código
venv\Scripts\activate
En macOS/Linux:

Copiar código
source venv/bin/activate

Instalar las dependencias:

pip install -r requirements.txt

Paso 3: Configurar las Credenciales
En el archivo llamado generarCredenciales.py se deben reemplazar los valores de las variales según su entorno. En el archivo se encuentran las por defecto al tratarse de un entorno DEV para facilitar la puesta en marcha.
db_uri 
db_user 
db_password 
Ejecutar el archivo generarCredenciales.py
python generarCredenciales.py

Se generará un archivo key.key y config.json que deben colocarse en la misma ruta que app.py y dashboard.py

Paso 4: Ejecutar la API y el Dashboard
Ejecuta la API:
python app.py
En otro terminal, ejecuta el dashboard:
python dashboard.py



