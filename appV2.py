from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
import json
from cryptography.fernet import Fernet

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_encrypted_config():
    """
    Cargar y desencriptar la configuración de la base de datos desde archivos encriptados.
    """
    try:
        with open('key.key', 'rb') as key_file:
            key = key_file.read()

        cipher_suite = Fernet(key)

        with open('config.json', 'r') as config_file:
            config = json.load(config_file)

        db_uri = cipher_suite.decrypt(config['db_uri_flask'].encode('utf-8')).decode('utf-8')
        db_user = cipher_suite.decrypt(config['db_user'].encode('utf-8')).decode('utf-8')
        db_password = cipher_suite.decrypt(config['db_password'].encode('utf-8')).decode('utf-8')
        logger.info(db_uri)
        logger.info(db_user)
        logger.info(db_password)

        return db_uri, db_user, db_password
    except Exception as e:
        logger.error("Error al cargar y desencriptar la configuración: %s", e)
        raise

# Cargar y desencriptar las credenciales de la base de datos
db_uri, db_user, db_password = load_encrypted_config()

# Verificar que las variables no están vacías
if not db_uri or not db_user or not db_password:
    logger.error("La configuración de la base de datos no está completa.")
    raise ValueError("La configuración de la base de datos no está completa.")


# Configurar la aplicación Flask y la base de datos
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@{db_uri}'
db = SQLAlchemy(app)

# Definición del modelo
class Vulnerabilidad(db.Model):
    __tablename__ = 'vulnerabilidades'  # Nombre de la tabla en la base de datos

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(255))
    vendor_project = db.Column(db.String(255))
    product = db.Column(db.String(255))
    vulnerability_name = db.Column(db.String(1024))
    date_added = db.Column(db.Date)
    short_description = db.Column(db.Text)
    required_action = db.Column(db.Text)
    due_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    grp = db.Column(db.Integer)
    pub_date = db.Column(db.Date)
    cvss = db.Column(db.Float)
    cwe = db.Column(db.String(255))
    vector = db.Column(db.String(255))
    complexity = db.Column(db.String(255))
    severity = db.Column(db.String(255))

@app.route('/vulnerabilidades', methods=['POST'])
def agregar_vulnerabilidad():
    """
    Endpoint para agregar una nueva vulnerabilidad.
    """
    data = request.json
    logger.info("Agregando nueva vulnerabilidad: %s", data)
    nueva_vuln = Vulnerabilidad(
        cve_id=data['cve_id'],
        vendor_project=data['vendor_project'],
        product=data['product'],
        vulnerability_name=data['vulnerability_name'],
        date_added=datetime.strptime(data['date_added'], '%Y-%m-%d'),
        short_description=data['short_description'],
        required_action=data['required_action'],
        due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
        notes=data.get('notes'),
        grp=data['grp'],
        pub_date=datetime.strptime(data['pub_date'], '%Y-%m-%d') if data['pub_date'] else None,
        cvss=data['cvss'],
        cwe=data['cwe'],
        vector=data['vector'],
        complexity=data['complexity'],
        severity=data['severity']
    )
    db.session.add(nueva_vuln)
    db.session.commit()
    verificar_patron(data)
    logger.info("Vulnerabilidad agregada exitosamente: %s", nueva_vuln)
    return jsonify({'mensaje': 'Vulnerabilidad agregada'}), 201

@app.route('/vulnerabilidades', methods=['GET'])
def obtener_vulnerabilidades():
    """
    Endpoint para obtener todas las vulnerabilidades.
    """
    logger.info("Obteniendo todas las vulnerabilidades")
    vulnerabilidades = Vulnerabilidad.query.all()
    resultado = [{
        'id': v.id,
        'cve_id': v.cve_id,
        'vendor_project': v.vendor_project,
        'product': v.product,
        'vulnerability_name': v.vulnerability_name,
        'date_added': v.date_added,
        'short_description': v.short_description,
        'required_action': v.required_action,
        'due_date': v.due_date,
        'notes': v.notes,
        'grp': v.grp,
        'pub_date': v.pub_date,
        'cvss': v.cvss,
        'cwe': v.cwe,
        'vector': v.vector,
        'complexity': v.complexity,
        'severity': v.severity
    } for v in vulnerabilidades]
    logger.info("Vulnerabilidades obtenidas exitosamente: %d", len(resultado))
    return jsonify(resultado)

@app.route('/vulnerabilidades/<int:id>', methods=['PUT'])
def actualizar_vulnerabilidad(id):
    """
    Endpoint para actualizar una vulnerabilidad existente.
    """
    data = request.json
    logger.info("Actualizando vulnerabilidad con ID %d: %s", id, data)
    vulnerabilidad = Vulnerabilidad.query.get(id)
    if vulnerabilidad is None:
        logger.warning("Vulnerabilidad con ID %d no encontrada", id)
        return jsonify({'mensaje': 'Vulnerabilidad no encontrada'}), 404
    vulnerabilidad.cve_id = data.get('cve_id', vulnerabilidad.cve_id)
    vulnerabilidad.vendor_project = data.get('vendor_project', vulnerabilidad.vendor_project)
    vulnerabilidad.product = data.get('product', vulnerabilidad.product)
    vulnerabilidad.vulnerability_name = data.get('vulnerability_name', vulnerabilidad.vulnerability_name)
    vulnerabilidad.date_added = datetime.strptime(data.get('date_added', vulnerabilidad.date_added.strftime('%Y-%m-%d')), '%Y-%m-%d')
    vulnerabilidad.short_description = data.get('short_description', vulnerabilidad.short_description)
    vulnerabilidad.required_action = data.get('required_action', vulnerabilidad.required_action)
    vulnerabilidad.due_date = datetime.strptime(data.get('due_date', vulnerabilidad.due_date.strftime('%Y-%m-%d')), '%Y-%m-%d')
    vulnerabilidad.notes = data.get('notes', vulnerabilidad.notes)
    vulnerabilidad.grp = data.get('grp', vulnerabilidad.grp)
    vulnerabilidad.pub_date = datetime.strptime(data.get('pub_date', vulnerabilidad.pub_date.strftime('%Y-%m-%d')), '%Y-%m-%d') if data.get('pub_date') else vulnerabilidad.pub_date
    vulnerabilidad.cvss = data.get('cvss', vulnerabilidad.cvss)
    vulnerabilidad.cwe = data.get('cwe', vulnerabilidad.cwe)
    vulnerabilidad.vector = data.get('vector', vulnerabilidad.vector)
    vulnerabilidad.complexity = data.get('complexity', vulnerabilidad.complexity)
    vulnerabilidad.severity = data.get('severity', vulnerabilidad.severity)
    db.session.commit()
    logger.info("Vulnerabilidad actualizada exitosamente: %s", vulnerabilidad)
    return jsonify({'mensaje': 'Vulnerabilidad actualizada'})

@app.route('/vulnerabilidades/<int:id>', methods=['DELETE'])
def eliminar_vulnerabilidad(id):
    """
    Endpoint para eliminar una vulnerabilidad existente.
    """
    logger.info("Eliminando vulnerabilidad con ID %d", id)
    vulnerabilidad = Vulnerabilidad.query.get(id)
    if vulnerabilidad is None:
        logger.warning("Vulnerabilidad con ID %d no encontrada", id)
        return jsonify({'mensaje': 'Vulnerabilidad no encontrada'}), 404
    db.session.delete(vulnerabilidad)
    db.session.commit()
    logger.info("Vulnerabilidad eliminada exitosamente: %s", vulnerabilidad)
    return jsonify({'mensaje': 'Vulnerabilidad eliminada'})

def verificar_patron(vulnerabilidad):
    """
    Verifica si una vulnerabilidad coincide con un patrón específico y genera una alerta si es necesario.
    """
    logger.info("Verificando patrón para vulnerabilidad: %s", vulnerabilidad)
    if vulnerabilidad['severity'] == 'CRITICAL' and 'NETWORK' in vulnerabilidad['vector']:
        generar_alerta(vulnerabilidad)

def generar_alerta(vulnerabilidad):
    """
    Genera una alerta para una vulnerabilidad crítica.
    """
    logger.info("Generando alerta para vulnerabilidad crítica: %s", vulnerabilidad)
    print(f"Alerta: Vulnerabilidad crítica detectada: {vulnerabilidad['vulnerability_name']}")

if __name__ == '__main__':
    # Crear todas las tablas si no existen
    # db.create_all()
    logger.info("Iniciando la aplicación Flask")
    app.run(debug=True)
