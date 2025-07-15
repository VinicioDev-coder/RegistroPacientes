from flask import Flask, request, jsonify, send_file
from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import json
import os
import re
import hashlib
import time
import io
import qrcode
from datetime import datetime
import logging
import jwt
from functools import wraps
from threading import Lock

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)

# CORS configurado para producción
CORS(app, origins=[
    'https://tu-dominio.onrender.com',  # Reemplaza con tu dominio real
    'http://127.0.0.1:5500', 
    'http://localhost:5500', 
    'http://127.0.0.1:3000', 
    'http://localhost:3000'
])

@app.route('/')
def home():
    return render_template('index.html')

# Esto es necesario para que funcione en Replit
app.run(host='0.0.0.0', port=81)

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Configuraciones - USA VARIABLES DE ENTORNO EN PRODUCCIÓN
SECRET = os.getenv('APP_SECRET', 'your-super-secret-key-here-change-in-production')
USERS = {
    'admin': os.getenv('ADMIN_PASSWORD', '1234'),
    'medico': os.getenv('MEDICO_PASSWORD', 'doc2024'),
    'enfermero': os.getenv('ENFERMERO_PASSWORD', 'nurse123')
}

# Archivo JSON para almacenar datos
JSON_FILE = 'pacientes.json'
json_lock = Lock()

# Validaciones
NOMBRE_RE = re.compile(r"^[A-Za-zÁÉÍÓÚáéíóúÑñ ]{2,50}$")
SINTOMA_RE = re.compile(r"^[A-Za-z0-9ÁÉÍÓÚáéíóúÑñ.,\- ]{3,200}$")
SINTOMAS_VALIDOS = [
    'fiebre', 'dolor de cabeza', 'tos', 'dolor de garganta', 'fatiga',
    'nauseas', 'vomito', 'diarrea', 'dolor abdominal', 'mareos',
    'dolor muscular', 'congestion nasal', 'perdida del gusto',
    'perdida del olfato', 'dificultad respiratoria'
]

# Control de acceso
blacklist = set()
failed_attempts = {}
APK_URL = "https://apiregistropacientes.onrender.com"

def init_json_file():
    """Inicializa el archivo JSON si no existe"""
    try:
        if not os.path.exists(JSON_FILE):
            with open(JSON_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            logging.info("Archivo JSON inicializado")
        else:
            # Verificar que el archivo sea válido
            with open(JSON_FILE, 'r', encoding='utf-8') as f:
                json.load(f)
            logging.info("Archivo JSON cargado correctamente")
    except Exception as e:
        logging.error(f"Error inicializando JSON: {str(e)}")
        # Crear archivo vacío si hay error
        with open(JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)

def load_patients():
    """Cargar pacientes desde JSON"""
    try:
        with json_lock:
            if not os.path.exists(JSON_FILE):
                return []
            with open(JSON_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"Error cargando pacientes: {str(e)}")
        return []

def save_patients(patients):
    """Guardar pacientes en JSON"""
    try:
        with json_lock:
            with open(JSON_FILE, 'w', encoding='utf-8') as f:
                json.dump(patients, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error guardando pacientes: {str(e)}")
        return False

def create_token(user, token_type='access', minutes=5):
    """Crear token JWT"""
    try:
        payload = {
            'sub': user,
            'type': token_type,
            'exp': int(time.time() + minutes * 60),
            'iat': int(time.time())
        }
        return jwt.encode(payload, SECRET, algorithm='HS256')
    except Exception as e:
        logging.error(f"Error creando token: {str(e)}")
        return None

def verify_token(token, token_type='access'):
    """Verificar token JWT"""
    try:
        if not token:
            return None
            
        if token in blacklist:
            return None
        
        payload = jwt.decode(token, SECRET, algorithms=['HS256'])
        
        if payload.get('type') != token_type:
            return None
        
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'expired'
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        logging.error(f"Error verificando token: {str(e)}")
        return None

def check_block(ip):
    """Verifica si IP está bloqueada"""
    if ip not in failed_attempts:
        return False
    
    info = failed_attempts[ip]
    if info['blocked_until'] > time.time():
        return True
    
    if info['blocked_until'] > 0 and info['blocked_until'] <= time.time():
        failed_attempts.pop(ip, None)
    
    return False

def jwt_required(f):
    """Decorator para autenticación JWT"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Obtener IP real considerando proxies de Render
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip:
                ip = ip.split(',')[0].strip()
            else:
                ip = get_remote_address()
            
            # Verificar bloqueo
            if check_block(ip):
                tiempo_restante = int(failed_attempts[ip]['blocked_until'] - time.time())
                return jsonify({
                    'error': 'Usuario bloqueado',
                    'tiempo_restante': tiempo_restante
                }), 403
            
            # Obtener token
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': 'Token requerido'}), 401
            
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Formato de token inválido'}), 401
            
            # Verificar token
            result = verify_token(token)
            
            if result is None:
                return jsonify({'error': 'Token inválido'}), 401
            elif result == 'expired':
                return jsonify({'error': 'Token expirado'}), 401
            
            request.current_user = result
            return f(*args, **kwargs)
            
        except Exception as e:
            logging.error(f"Error en auth: {str(e)}")
            return jsonify({'error': 'Error interno'}), 500
    
    return decorated_function

def validate_input(datos):
    """Validar entrada"""
    errores = []
    
    if not isinstance(datos, dict):
        return ["Formato inválido"]
    
    nombre = datos.get("nombre", "").strip() if datos.get("nombre") else ""
    sintoma = datos.get("sintoma", "").strip().lower() if datos.get("sintoma") else ""
    
    if not nombre:
        errores.append("Nombre requerido")
    elif not NOMBRE_RE.fullmatch(nombre):
        errores.append("Nombre inválido (2-50 caracteres, solo letras)")
    
    if not sintoma:
        errores.append("Síntoma requerido")
    elif not SINTOMA_RE.fullmatch(sintoma):
        errores.append("Síntoma con caracteres inválidos")
    elif sintoma not in SINTOMAS_VALIDOS:
        errores.append(f"Síntoma no válido. Disponibles: {', '.join(SINTOMAS_VALIDOS)}")
    
    return errores

def save_patient(nombre, sintoma, ip_address, usuario):
    """Guardar paciente en JSON"""
    try:
        patients = load_patients()
        
        # Generar ID único
        if patients:
            new_id = max(p.get('id', 0) for p in patients) + 1
        else:
            new_id = 1
        
        # Generar hash de sesión
        session_data = f"{nombre}{sintoma}{time.time()}"
        hash_session = hashlib.sha256(session_data.encode()).hexdigest()[:16]
        
        # Crear registro
        new_patient = {
            'id': new_id,
            'nombre': nombre,
            'sintoma': sintoma,
            'timestamp': datetime.now().isoformat(),
            'ip_address': ip_address,
            'hash_session': hash_session,
            'usuario_registro': usuario
        }
        
        patients.append(new_patient)
        
        if save_patients(patients):
            return new_id, hash_session
        else:
            return None, None
            
    except Exception as e:
        logging.error(f"Error guardando paciente: {str(e)}")
        return None, None

def get_patient(nombre):
    """Obtener paciente desde JSON"""
    try:
        patients = load_patients()
        
        # Buscar el paciente más reciente con ese nombre
        matching_patients = [p for p in patients if p['nombre'].lower() == nombre.lower()]
        
        if matching_patients:
            # Ordenar por timestamp descendente y tomar el más reciente
            latest_patient = max(matching_patients, key=lambda x: x['timestamp'])
            return {
                'nombre': latest_patient['nombre'],
                'sintoma': latest_patient['sintoma'],
                'timestamp': latest_patient['timestamp'],
                'usuario_registro': latest_patient['usuario_registro']
            }
        return None
        
    except Exception as e:
        logging.error(f"Error consultando paciente: {str(e)}")
        return None

def get_patients_count():
    """Obtener cantidad total de pacientes"""
    try:
        patients = load_patients()
        return len(patients)
    except Exception as e:
        logging.error(f"Error contando pacientes: {str(e)}")
        return 0

@app.before_request
def log_request():
    """Log de peticiones"""
    logging.info(f"{request.method} {request.path} desde {request.remote_addr}")

# ENDPOINTS
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """Login con JWT"""
    try:
        # Obtener IP real considerando proxies
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip:
            ip = ip.split(',')[0].strip()
        else:
            ip = get_remote_address()
        
        if check_block(ip):
            tiempo_restante = int(failed_attempts[ip]['blocked_until'] - time.time())
            return jsonify({
                'error': 'Usuario bloqueado',
                'tiempo_restante': tiempo_restante
            }), 403
        
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        datos = request.get_json()
        if not datos:
            return jsonify({'error': 'JSON requerido'}), 400
        
        username = datos.get('username')
        password = datos.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username y password requeridos'}), 400
        
        # Verificar credenciales
        if username not in USERS or USERS[username] != password:
            if ip not in failed_attempts:
                failed_attempts[ip] = {'count': 0, 'blocked_until': 0}
            
            failed_attempts[ip]['count'] += 1
            
            if failed_attempts[ip]['count'] >= 3:
                failed_attempts[ip]['blocked_until'] = time.time() + 300
                return jsonify({'error': 'Bloqueado por 5 minutos'}), 403
            
            return jsonify({
                'error': 'Credenciales inválidas',
                'intentos_restantes': 3 - failed_attempts[ip]['count']
            }), 401
        
        # Limpiar intentos fallidos
        if ip in failed_attempts:
            failed_attempts.pop(ip, None)
        
        # Generar tokens
        access_token = create_token(username, 'access', 5)
        refresh_token = create_token(username, 'refresh', 60)
        
        if not access_token or not refresh_token:
            return jsonify({'error': 'Error generando tokens'}), 500
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 300,
            'token_type': 'Bearer',
            'user': username
        }), 200
        
    except Exception as e:
        logging.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/pacientes/<int:patient_id>", methods=["PUT"])
@limiter.limit("20 per minute")
@jwt_required
def editar_paciente(patient_id):
    """Editar paciente existente"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        datos = request.get_json()
        if not datos:
            return jsonify({'error': 'JSON requerido'}), 400
        
        # Validar entrada
        errores = validate_input(datos)
        if errores:
            return jsonify({
                'error': 'Datos inválidos',
                'detalles': errores
            }), 400
        
        nombre = datos["nombre"].strip().title()
        sintoma = datos["sintoma"].strip().lower()
        
        # Cargar pacientes
        patients = load_patients()
        
        # Buscar paciente por ID
        patient_found = False
        for patient in patients:
            if patient.get('id') == patient_id:
                patient['nombre'] = nombre
                patient['sintoma'] = sintoma
                patient['timestamp'] = datetime.now().isoformat()
                patient['usuario_modificacion'] = request.current_user
                patient_found = True
                break
        
        if not patient_found:
            return jsonify({'error': 'Paciente no encontrado'}), 404
        
        # Guardar cambios
        if save_patients(patients):
            return jsonify({
                'estado': 'actualizado',
                'mensaje': f'Paciente {nombre} actualizado exitosamente',
                'id': patient_id
            }), 200
        else:
            return jsonify({'error': 'Error guardando cambios'}), 500
        
    except Exception as e:
        logging.error(f"Error editando paciente: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/pacientes/<int:patient_id>", methods=["DELETE"])
@limiter.limit("20 per minute")
@jwt_required
def eliminar_paciente(patient_id):
    """Eliminar paciente"""
    try:
        # Cargar pacientes
        patients = load_patients()
        
        # Buscar y eliminar paciente
        original_count = len(patients)
        patients = [p for p in patients if p.get('id') != patient_id]
        
        if len(patients) == original_count:
            return jsonify({'error': 'Paciente no encontrado'}), 404
        
        # Guardar cambios
        if save_patients(patients):
            return jsonify({
                'estado': 'eliminado',
                'mensaje': 'Paciente eliminado exitosamente',
                'id': patient_id
            }), 200
        else:
            return jsonify({'error': 'Error eliminando paciente'}), 500
        
    except Exception as e:
        logging.error(f"Error eliminando paciente: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute")
def refresh():
    """Renovar token"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        datos = request.get_json()
        if not datos:
            return jsonify({'error': 'JSON requerido'}), 400
        
        refresh_token = datos.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'refresh_token requerido'}), 400
        
        # Verificar refresh token
        result = verify_token(refresh_token, 'refresh')
        
        if result is None:
            return jsonify({'error': 'Refresh token inválido'}), 401
        elif result == 'expired':
            return jsonify({'error': 'Refresh token expirado'}), 401
        
        # Generar nuevo access token
        new_access_token = create_token(result, 'access', 5)
        if not new_access_token:
            return jsonify({'error': 'Error generando nuevo token'}), 500
        
        return jsonify({
            'access_token': new_access_token,
            'expires_in': 300,
            'token_type': 'Bearer',
            'user': result
        }), 200
        
    except Exception as e:
        logging.error(f"Error en refresh: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/logout", methods=["POST"])
@jwt_required
def logout():
    """Cerrar sesión"""
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                access_token = auth_header.split(' ')[1]
                blacklist.add(access_token)
            except IndexError:
                pass
        
        if request.is_json:
            datos = request.get_json()
            if datos:
                refresh_token = datos.get('refresh_token')
                if refresh_token:
                    blacklist.add(refresh_token)
        
        return jsonify({'message': 'Sesión cerrada'}), 200
        
    except Exception as e:
        logging.error(f"Error en logout: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/registro", methods=["POST"])
@limiter.limit("30 per minute")
@jwt_required
def registrar_paciente():
    """Registrar paciente"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type debe ser application/json'}), 400
        
        datos = request.get_json()
        if not datos:
            return jsonify({'error': 'JSON requerido'}), 400
        
        # Validar entrada
        errores = validate_input(datos)
        if errores:
            return jsonify({
                'error': 'Datos inválidos',
                'detalles': errores
            }), 400
        
        nombre = datos["nombre"].strip().title()
        sintoma = datos["sintoma"].strip().lower()
        
        # Obtener IP real
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = get_remote_address() or '127.0.0.1'
        
        # Guardar paciente
        registro_id, hash_session = save_patient(nombre, sintoma, ip_address, request.current_user)
        
        if not registro_id:
            return jsonify({'error': 'Error guardando paciente'}), 500
        
        return jsonify({
            'estado': 'registrado',
            'mensaje': f'Paciente {nombre} registrado exitosamente',
            'id_registro': registro_id,
            'usuario': request.current_user,
            'timestamp': datetime.now().isoformat()
        }), 201
        
    except Exception as e:
        logging.error(f"Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/consulta", methods=["GET"])
@limiter.limit("30 per minute")
@jwt_required
def consultar_paciente():
    """Consultar paciente"""
    try:
        nombre = request.args.get('nombre', '').strip()
        
        if not nombre:
            return jsonify({'error': 'Parámetro nombre requerido'}), 400
        
        if not NOMBRE_RE.fullmatch(nombre):
            return jsonify({'error': 'Formato de nombre inválido'}), 400
        
        paciente = get_patient(nombre.title())
        
        if not paciente:
            return jsonify({'error': 'Paciente no encontrado'}), 404
        
        return jsonify({
            'nombre': paciente['nombre'],
            'sintoma': paciente['sintoma'],
            'fecha_registro': paciente['timestamp'],
            'usuario_registro': paciente['usuario_registro'],
            'consultado_por': request.current_user,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error en consulta: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/apk", methods=["GET"])
@limiter.limit("20 per minute")
@jwt_required
def generar_qr_apk():
    """Generar QR para APK"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(APK_URL)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        
        return send_file(
            buf,
            mimetype='image/png',
            as_attachment=False,
            download_name='medsecure_qr.png'
        )
        
    except Exception as e:
        logging.error(f"Error generando QR: {str(e)}")
        return jsonify({'error': 'Error generando QR'}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check"""
    try:
        return jsonify({
            'estado': 'activo',
            'servicio': 'API Registro Pacientes',
            'version': '3.0.1',
            'almacenamiento': 'JSON',
            'timestamp': datetime.now().isoformat(),
            'endpoints': ['/login', '/refresh', '/logout', '/registro', '/consulta', '/apk', '/health', '/status']
        }), 200
    except Exception as e:
        logging.error(f"Error en health check: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/status", methods=["GET"])
@jwt_required
def status():
    """Estado del sistema"""
    try:
        total_pacientes = get_patients_count()
        
        blocked_ips = []
        current_time = time.time()
        
        for ip, info in failed_attempts.items():
            if info['blocked_until'] > current_time:
                blocked_ips.append({
                    'ip': ip,
                    'tiempo_restante': int(info['blocked_until'] - current_time)
                })
        
        return jsonify({
            'estado': 'operativo',
            'total_pacientes': total_pacientes,
            'ips_bloqueadas': len(blocked_ips),
            'tokens_revocados': len(blacklist),
            'usuario_consulta': request.current_user,
            'archivo_datos': JSON_FILE,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error en status: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

@app.route("/pacientes", methods=["GET"])
@jwt_required
def listar_pacientes():
    """Listar todos los pacientes (solo para administrador)"""
    try:
        if request.current_user != 'admin':
            return jsonify({'error': 'Acceso denegado'}), 403
        
        patients = load_patients()
        return jsonify({
            'total': len(patients),
            'pacientes': patients
        }), 200
        
    except Exception as e:
        logging.error(f"Error listando pacientes: {str(e)}")
        return jsonify({'error': 'Error interno'}), 500

# Manejadores de error
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Límite de peticiones excedido'}), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint no encontrado'}), 404

@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Error 500: {str(e)}")
    return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == "__main__":
    # Inicializar archivo JSON
    init_json_file()
    
    # Obtener puerto de las variables de entorno (necesario para Render)
    port = int(os.getenv('PORT', 5000))
    
    print("=" * 50)
    print("API REGISTRO PACIENTES (JSON) - VERSION 3.0.1")
    print("=" * 50)
    print("Usuarios disponibles:")
    for user in USERS.keys():
        print(f"  - {user}")
    print(f"\nArchivo de datos: {JSON_FILE}")
    print(f"Puerto: {port}")
    print("\nEndpoints disponibles:")
    print("  POST /login - Autenticación")
    print("  POST /refresh - Renovar token")
    print("  POST /logout - Cerrar sesión")
    print("  POST /registro - Registrar paciente")
    print("  GET /consulta?nombre=X - Consultar paciente")
    print("  GET /apk - Generar QR de APK")
    print("  GET /health - Estado API")
    print("  GET /status - Estadísticas")
    print("  GET /pacientes - Listar todos (solo admin)")
    print("=" * 50)
    
    # Configuración para producción en Render
    debug_mode = os.getenv('FLASK_ENV') != 'production'
    
    # Ejecutar aplicación
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug_mode
    )
