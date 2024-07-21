import requests

def test_firewall():
    # Test allowed packet
    response = requests.post('http://localhost:5000/process_packet', json={
        'src_ip': '192.168.1.2',
        'dst_ip': '10.0.0.1',
        'src_port': 8080,
        'dst_port': 80,
        'protocol': 'TCP',
        'payload': 'test'
    })
    print("Allowed packet test:", response.json())

    # Test denied packet
    response = requests.post('http://localhost:5000/process_packet', json={
        'src_ip': '192.168.1.1',
        'dst_ip': '10.0.0.1',
        'src_port': 8080,
        'dst_port': 80,
        'protocol': 'TCP',
        'payload': 'test'
    })
    print("Denied packet test:", response.json())

if __name__ == "__main__":
    test_firewall()
