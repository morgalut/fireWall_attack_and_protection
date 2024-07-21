import logging

# Configure logging
logging.basicConfig(filename='C:\\Users\\Mor\\Desktop\\OpenFlowFirewall\\firewall_project\\attack_testing\\attack_test.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_attack_result(result, success=True):
    if success:
        logging.info(f"Successful Attack: {result}")
    else:
        logging.warning(f"Failed Attack: {result}")

def log_error(error):
    logging.error(f"Error occurred: {error}")
