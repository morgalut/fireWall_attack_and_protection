import requests

def send_payloads():
    payloads = [
        'malformed_payload',
        'SQL_INJECTION_PAYLOAD',
        'XSS_PAYLOAD'
    ]
    
    for payload in payloads:
        response = requests.post('http://localhost:5000/process_packet', json={
            'src_ip': '192.168.1.3',
            'dst_ip': '10.0.0.1',
            'src_port': 8080,
            'dst_port': 80,
            'protocol': 'TCP',
            'payload': payload
        })
        result = response.json().get('result', '')
        
        # Determine if the penetration is successful or failed
        if "ALLOWED" in result:
            print(f"Failed Penetration Test: Payload '{payload}' was allowed")
        else:
            print(f"Successful Penetration Test: Payload '{payload}' was correctly denied")

if __name__ == "__main__":
    send_payloads()
