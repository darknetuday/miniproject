# WAF Fingerprinting Protection Demo

This application demonstrates a simple Web Application Firewall (WAF) implementation with protection against fingerprinting attempts.

## Features

- Basic WAF implementation
- Fingerprinting detection
- IP blocking for suspicious activity
- Protection against common WAF fingerprinting tools
- Logging of suspicious activities

## Installation

1. Clone this repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

Start the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Testing the WAF

You can test the WAF protection by making requests with different headers:

1. Normal request:
   ```bash
   curl http://localhost:5000/
   ```

2. Request with suspicious User-Agent:
   ```bash
   curl -H "User-Agent: wafw00f" http://localhost:5000/
   ```

3. Request with suspicious header:
   ```bash
   curl -H "X-WAF-Test: true" http://localhost:5000/
   ```

## API Endpoints

- `GET /`: Main application route
- `GET /api/data`: Example protected API endpoint

## Security Features

- Detects common WAF fingerprinting patterns
- Blocks IPs attempting fingerprinting
- Monitors suspicious headers
- Logs security events

## Note

This is a demonstration application and should not be used in production without additional security measures and proper configuration. 
