from flask import Flask, request, jsonify
from firewall.firewall import Firewall
from firewall.packet import Packet
from firewall.rule import RuleType
from firewall.enums import Action
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='C:\\Users\\Mor\\Desktop\\OpenFlowFirewall\\firewall_project\\logs\\firewall.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the firewall
firewall = Firewall()
firewall.add_rule(RuleType.IP, "192.168.1.1", Action.DENY)
firewall.add_rule(RuleType.PORT, 80, Action.LOG)
firewall.add_rule(RuleType.PROTOCOL, "TCP", Action.ALLOW)

# Function to send email notifications
def send_email(subject, body):
    sender_email = "worDfence@waba.com"
    receiver_email = "morgalut54@gmail.com"
    password = "your-email-password"  # Replace with the actual password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.waba.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
        logging.info("Email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

@app.route('/process_packet', methods=['POST'])
def process_packet():
    data = request.json
    packet = Packet(
        src_ip=data['src_ip'],
        dst_ip=data['dst_ip'],
        src_port=data['src_port'],
        dst_port=data['dst_port'],
        protocol=data['protocol'],
        payload=data['payload']
    )
    result = firewall.process_packet(packet)
    
    # Log the result
    log_msg = f"Processed packet from {packet.src_ip} to {packet.dst_ip}: {result}"
    logging.info(log_msg)
    
    # Print real-time information to the terminal
    print(f"Received packet: {packet.src_ip} -> {packet.dst_ip}")
    print(f"Result: {result}")
    
    return jsonify({'result': result})

@app.route('/test', methods=['GET'])
def test():
    # Simulate a test attempt
    logging.info("Test attempt started.")
    test_packet = Packet("192.168.1.2", "10.0.0.1", 8080, 80, "TCP", "test")
    result = firewall.process_packet(test_packet)
    log_msg = f"Test packet result: {result}"
    logging.info(log_msg)
    print(f"Test packet result: {result}")
    send_email("Firewall Test Report", log_msg)
    return jsonify({'result': result})

@app.route('/status', methods=['GET'])
def status():
    # Simulate status check
    log_msg = "Firewall is running smoothly."
    logging.info(log_msg)
    print(log_msg)
    send_email("Firewall Status Report", log_msg)
    return jsonify({'status': log_msg})

if __name__ == "__main__":
    app.run(port=5000)
