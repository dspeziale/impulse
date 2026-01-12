import requests
import json
from datetime import datetime
import urllib.parse

class TraccarClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        # Initial login
        self.login()

    def login(self):
        """Establish session"""
        try:
            # Traccar expects x-www-form-urlencoded
            # requests.post(url, data=payload) handles this automatically
            payload = {'email': self.username, 'password': self.password}
            
            response = self.session.post(f"{self.base_url}/api/session", data=payload, timeout=10)
            
            if response.status_code in [200, 201, 202]:
                print("Traccar Login Successful")
                return True
            else:
                print(f"Traccar Login Failed: {response.status_code}")
                # Optional: print response.text if specific debugging needed
                return False
                
            response.raise_for_status()
        except Exception as e:
            print(f"Traccar Login Exception: {e}")
            return False

    def get_devices(self):
        """Fetch all devices"""
        try:
            response = self.session.get(f"{self.base_url}/api/devices")
            if response.status_code == 401:
                self.login() # Retry login
                response = self.session.get(f"{self.base_url}/api/devices")
            
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Traccar Error (get_devices): {e}")
            return []

    def get_positions(self):
        """Fetch latest positions for all devices"""
        try:
            response = self.session.get(f"{self.base_url}/api/positions")
            if response.status_code == 401:
                self.login()
                response = self.session.get(f"{self.base_url}/api/positions")

            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Traccar Error (get_positions): {e}")
            return []

    def get_route(self, device_id, start_time, end_time):
        """
        Fetch route history.
        Dates must be ISO 8601 strings (e.g. 2024-01-01T08:00:00Z)
        """
        params = {
            'deviceId': device_id,
            'from': start_time,
            'to': end_time
        }
        try:
            response = self.session.get(f"{self.base_url}/api/reports/route", params=params)
            if response.status_code == 401:
                self.login()
                response = self.session.get(f"{self.base_url}/api/reports/route", params=params)

            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Traccar Error (get_route): {e}")
            return []
