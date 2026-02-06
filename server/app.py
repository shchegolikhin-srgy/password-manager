from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import uuid
from datetime import datetime, timedelta
import os
from cryptography.fernet import Fernet
import base64
import hashlib
import boto3
from dotenv import load_dotenv


app = Flask(__name__)
load_dotenv()
CORS(app)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'секретный ключ')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 24)))
jwt = JWTManager(app)


def get_encryption_key():
    secret = os.getenv('ENCRYPTION_SECRET', 'my-super-secret-encryption-key-for-passwords-2025')
    key = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key)

fernet = Fernet(get_encryption_key())

def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'postgres'),
        port=int(os.getenv('DB_PORT', 5432)),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'mysecretpassword'),
        dbname=os.getenv('DB_NAME', 'password_manager')
    )
    return conn

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username, and password are required'}), 400 
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        count = cursor.fetchone()[0]
        if count > 0:
            return jsonify({'error': 'Username already exists'}), 409
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO users (id, username, password_hash, is_active) VALUES (%s, %s, %s, %s)",
            (user_id, username, hashed_password, True)
        )
        conn.commit()
        token = create_access_token(identity=user_id)
        return jsonify({
            'token': token,
            'user': {
                'id': user_id,
                'username': username,
                'is_active': True
            },
            'message': 'Registration successful'
        }), 201 
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    device_info = data.get('deviceInfo', {})

    browser_version = device_info.get('browserVersion')
    browser_name = device_info.get('browserName')
    os_name = device_info.get('osName')
    os_version = device_info.get('osVersion')
    device_type = device_info.get('deviceType')
    device_name = device_info.get('deviceName')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            "SELECT id, username, password_hash, is_active FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401  
        if not user['is_active']:
            return jsonify({'error': 'Account is deactivated'}), 401
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

        cursor.execute(
            "SELECT id, is_active FROM trusted_devices WHERE user_id = %s AND browser_name = %s AND browser_version = %s AND device_type = %s AND device_name = %s AND os_name = %s AND os_version = %s",
            (user['id'], browser_name, browser_version, device_type, device_name, os_name, os_version)
        )
        trusted_device = cursor.fetchone()
        
        is_trusted_device = False
        if trusted_device:
            if trusted_device['is_active']:
                is_trusted_device = True
                cursor.execute(
                    "UPDATE trusted_devices SET last_seen_at = NOW() WHERE id = %s",
                    (trusted_device['id'],)
                )
            else:
                cursor.execute(
                    "INSERT INTO device_history (user_id, browser_version, browser_name, device_type, device_name, os_name, os_version, is_active, last_seen_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())",
                    (user['id'], browser_version, browser_name, device_type, device_name, os_name, os_version, False)
                )
        else:
            cursor.execute(
                "INSERT INTO device_history (user_id, browser_version, browser_name, device_type, device_name, os_name, os_version, is_active, last_seen_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())",
                (user['id'], browser_version, browser_name, device_type, device_name, os_name, os_version, True)
            )
        conn.commit()
        token = create_access_token(identity=str(user['id']))
        return jsonify({
            'token': token,
            'user': {
                'id': str(user['id']),
                'username': user['username'],
                'is_active': user['is_active']
            },
            'device_trusted': is_trusted_device,
            'message': 'Login successful'
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/passwords', methods=['GET'])
@jwt_required()
def get_passwords():
    current_user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            "SELECT id, service, username, encrypted_password FROM encrypted_passwords  WHERE user_id = %s ORDER BY created_at DESC",
            (current_user_id,)
        )
        rows = cursor.fetchall()
        passwords = []
        for row in rows:
            try:
                decrypted_password = fernet.decrypt(row['encrypted_password'].encode('utf-8')).decode('utf-8')
                passwords.append({
                    'id': row['id'],
                    'service': row['service'],
                    'username': row['username'],
                    'password': decrypted_password
                })
            except Exception as e:
                passwords.append({
                    'id': row['id'],
                    'service': row['service'],
                    'username': row['username'],
                    'password': '[DECRYPTION ERROR]'
                })
        return jsonify([dict(row) for row in passwords]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/passwords', methods=['POST'])
@jwt_required()
def create_password():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    service = data.get('service')
    username = data.get('username')
    password = data.get('password')
    
    if not service or not username or not password:
        return jsonify({'error': 'Service, username, and password are required'}), 400
    try:
        encrypted_password = fernet.encrypt(password.encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({'error': 'Encryption failed'}), 500
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO encrypted_passwords  (user_id, service, username, encrypted_password) VALUES (%s, %s, %s, %s) RETURNING id",
            (current_user_id, service, username, encrypted_password)
        )
        password_id = cursor.fetchone()[0]
        conn.commit()
        
        return jsonify({
            'id': password_id,
            'service': service,
            'username': username,
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@jwt_required()
def delete_password(password_id):
    current_user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM encrypted_passwords  WHERE id = %s AND user_id = %s",
            (password_id, current_user_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'error': 'Password entry not found or not owned by user'}), 404
        return '', 204
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/devices/history', methods=['GET'])
@jwt_required()
def get_device_history():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            "SELECT id, browser_version, browser_name, device_type, device_name, os_name, os_version, is_active, created_at, last_seen_at FROM device_history WHERE user_id = %s ORDER BY created_at DESC",
            (current_user_id,)
        )
        history = cursor.fetchall()
        return jsonify({
            'history': history,
            'count': len(history)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/devices/trusted', methods=['GET'])
@jwt_required()
def get_trusted_devices():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute(
            "SELECT id, browser_version, browser_name, device_type, device_name, os_name, os_version, is_active, created_at, last_seen_at FROM trusted_devices WHERE user_id = %s ORDER BY created_at DESC",
            (current_user_id,)
        )
        devices = cursor.fetchall()
        return jsonify({
            'devices': devices,
            'count': len(devices)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/devices/trusted/<int:device_id>', methods=['DELETE'])
@jwt_required()
def remove_trusted_device(device_id):
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM trusted_devices WHERE id = %s AND user_id = %s",
            (device_id, current_user_id)
        )
        if cursor.rowcount == 0:
            return jsonify({'error': 'Device not found or access denied'}), 404
        conn.commit()
        return jsonify({'message': 'Device removed successfully'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/devices/trust-current', methods=['POST'])
@jwt_required()
def trust_current_device():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    device_info = data.get('deviceInfo', {})

    browser_version = device_info.get('browserVersion')
    browser_name = device_info.get('browserName')
    os_name = device_info.get('osName')
    os_version = device_info.get('osVersion')
    device_type = device_info.get('deviceType')
    device_name = device_info.get('deviceName')
    if not all([browser_name, device_type]):
        return jsonify({'error': 'Required device information is missing'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM trusted_devices WHERE user_id = %s AND browser_name = %s AND browser_version = %s AND device_type = %s AND device_name = %s AND os_name = %s AND os_version = %s",
            (current_user_id, browser_name, browser_version, device_type, device_name, os_name, os_version)
        )
        existing_device = cursor.fetchone()
        if existing_device:
            return jsonify({'error': 'Device already exists in trusted list'}), 409

        cursor.execute(
            "INSERT INTO trusted_devices (user_id, browser_version, browser_name, device_type, device_name, os_name, os_version, is_active) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (current_user_id, browser_version, browser_name, device_type, device_name, os_name, os_version, True)
        )
        conn.commit()

        return jsonify({'message': 'Current device added to trusted list'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/passwords/favorites', methods=['GET'])
@jwt_required()
def get_favorite_passwords():
    current_user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                fp.id,
                fp.user_id,
                fp.password_id,
                fp.created_at,
                ep.service,
                ep.username
            FROM favorite_passwords fp
            JOIN encrypted_passwords ep ON fp.password_id = ep.id
            WHERE fp.user_id = %s
            ORDER BY fp.created_at DESC;
        """, (current_user_id,))
        favorite_passwords = cursor.fetchall()
        result = []
        for row in favorite_passwords:
            result.append({
                'id': row[0],
                'user_id': row[1],
                'password_id': row[2],
                'created_at': row[3],
                'service_name': row[4],
                'username': row[5]
            })
        return jsonify({'favorite_passwords': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/passwords/favorites', methods=['POST'])
@jwt_required()
def add_favorite_password():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    password_id = data.get('password_id')
    if not password_id:
        return jsonify({'error': 'Password ID is required'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM encrypted_passwords WHERE id = %s AND user_id = %s",
            (password_id, current_user_id)
        )
        password = cursor.fetchone()
        if not password:
            return jsonify({'error': 'Password not found or does not belong to user'}), 404
        cursor.execute(
            "SELECT id FROM favorite_passwords WHERE user_id = %s AND password_id = %s",
            (current_user_id, password_id)
        )
        existing_favorite = cursor.fetchone()
        if existing_favorite:
            return jsonify({'error': 'Password already exists in favorites'}), 409
        cursor.execute(
            "INSERT INTO favorite_passwords (user_id, password_id) VALUES (%s, %s)",
            (current_user_id, password_id)
        )
        conn.commit()
        return jsonify({'message': 'Password added to favorites'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/passwords/favorites/<int:password_id>', methods=['DELETE'])
@jwt_required()
def remove_favorite_password(password_id):
    current_user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM favorite_passwords WHERE user_id = %s AND password_id = %s",
            (current_user_id, password_id)
        )
        deleted_rows = cursor.rowcount
        conn.commit()
        if deleted_rows == 0:
            return jsonify({'error': 'Favorite password not found'}), 404
        return jsonify({'message': 'Password removed from favorites'}), 200
    except Exception as e:
        conn.rollback()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM favorite_passwords WHERE user_id = %s AND password_id = %s",
            (current_user_id, password_id)
        )
        favorite = cursor.fetchone()
        if favorite:
            return jsonify({'is_favorite': True}), 200
        else:
            return jsonify({'is_favorite': False}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)
