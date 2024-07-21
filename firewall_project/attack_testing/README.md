# Firewall Attack Testing

This project is designed to test the robustness of the firewall implementation by simulating various attack scenarios.

## Setup

- Ensure the firewall server is running on `http://localhost:5000`.
- Install necessary Python packages (`requests`).

## Scripts

- `test_firewall.py`: Tests basic firewall functionality.
- `test_payloads.py`: Sends different payloads to test for vulnerabilities.
- `test_utils.py`: Contains utility functions for logging and error handling.

## Running Tests

```bash
python test_firewall.py
python test_payloads.py
```

## Logs
Logs are saved to `attack_test.log`.
