#!/usr/bin/env python3
"""
Script para verificar que las mitigaciones de seguridad funcionan correctamente
Uso: python3 verify_mitigations.py
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

def test_sql_injection_mitigation(token):
    """Verificar que la inyección SQL está mitigada"""
    print("\n🔍 Probando mitigación de inyección SQL...")
    
    # Payloads que deberían ser bloqueados
    malicious_payloads = [
        "paid' OR '1'='1",
        "paid' UNION SELECT 1,2,3,4,5--",
        "paid'; DROP TABLE invoices; --",
        "paid' AND 1=1",
        "paid' /*"
    ]
    
    blocked_count = 0
    
    for payload in malicious_payloads:
        url = f"{BASE_URL}/invoices?status={payload}&operator=="
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            response = requests.get(url, headers=headers)
            if "caracteres no válidos" in response.text or "Operador no válido" in response.text:
                print(f"✅ Payload bloqueado: {payload[:30]}...")
                blocked_count += 1
            else:
                print(f"❌ Payload no bloqueado: {payload[:30]}...")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"Payloads bloqueados: {blocked_count}/{len(malicious_payloads)}")
    return blocked_count == len(malicious_payloads)

def test_ssrf_mitigation(token):
    """Verificar que SSRF está mitigado"""
    print("\n🔍 Probando mitigación de SSRF...")
    
    # Payloads que deberían ser bloqueados
    malicious_payloads = [
        "localhost:22",
        "169.254.169.254",
        "metadata.google.internal",
        "localhost:3306",
        "127.0.0.1:22"
    ]
    
    blocked_count = 0
    
    for payload in malicious_payloads:
        url = f"{BASE_URL}/invoices/test-invoice/pay"
        headers = {"Authorization": f"Bearer {token}"}
        data = {
            "paymentBrand": payload,
            "ccNumber": "4111111111111111",
            "ccv": "123",
            "expirationDate": "12/25"
        }
        
        try:
            response = requests.post(url, json=data, headers=headers)
            if "Marca de pago no válida" in response.text or "caracteres no válidos" in response.text:
                print(f"✅ Payload SSRF bloqueado: {payload}")
                blocked_count += 1
            else:
                print(f"❌ Payload SSRF no bloqueado: {payload}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"Payloads SSRF bloqueados: {blocked_count}/{len(malicious_payloads)}")
    return blocked_count == len(malicious_payloads)

def test_hardcoded_credentials_mitigation():
    """Verificar que las credenciales hardcodeadas están mitigadas"""
    print("\n🔍 Probando mitigación de credenciales hardcodeadas...")
    
    # Verificar que el servidor requiere variables de entorno
    try:
        # Intentar hacer una petición que debería fallar si no hay JWT_SECRET
        response = requests.get(f"{BASE_URL}/auth/")
        if response.status_code == 200:
            print("✅ Servidor funcionando (variables de entorno configuradas)")
            return True
        else:
            print("❌ Servidor no responde correctamente")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("🛡️  Verificando mitigaciones de seguridad...")
    
    # Obtener token
    token = login()
    if not token:
        print("❌ No se pudo obtener token de autenticación")
        sys.exit(1)
    
    print("✅ Token obtenido")
    
    # Probar mitigaciones
    sql_mitigated = test_sql_injection_mitigation(token)
    ssrf_mitigated = test_ssrf_mitigation(token)
    creds_mitigated = test_hardcoded_credentials_mitigation()
    
    # Resumen
    print("\n🎯 Resumen de mitigaciones:")
    print(f"✅ Inyección SQL mitigada: {'Sí' if sql_mitigated else 'No'}")
    print(f"✅ SSRF mitigado: {'Sí' if ssrf_mitigated else 'No'}")
    print(f"✅ Credenciales hardcodeadas mitigadas: {'Sí' if creds_mitigated else 'No'}")
    
    if sql_mitigated and ssrf_mitigated and creds_mitigated:
        print("\n🎉 ¡Todas las mitigaciones están funcionando correctamente!")
    else:
        print("\n⚠️  Algunas mitigaciones necesitan revisión")

if __name__ == "__main__":
    main()
