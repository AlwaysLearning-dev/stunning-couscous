"""
title: VirusTotal Hash Analysis Pipeline
author: open-webui
date: 2024-12-20
version: 1.0
license: MIT
description: A pipeline for querying VirusTotal API to analyze file hashes and extract associated IP addresses
requirements: requests, pydantic
"""

from typing import List, Dict, Any, Generator
import logging
import json
import os
from datetime import datetime
import requests
from pydantic import BaseModel

class Pipeline:
    class Valves(BaseModel):
        VT_API_KEY: str
        VT_BASE_URL: str
        LOG_LEVEL: str
        ENABLE_DEBUG: bool

    def __init__(self):
        # Initialize valves with environment variables or defaults
        self.valves = self.Valves(
            **{
                "VT_API_KEY": os.getenv("VT_API_KEY", ""),
                "VT_BASE_URL": os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3"),
                "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
                "ENABLE_DEBUG": os.getenv("ENABLE_DEBUG", "false").lower() == "true"
            }
        )

        # Setup logging
        logging.basicConfig(
            level=getattr(logging, self.valves.LOG_LEVEL),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    async def on_startup(self):
        """Verify API key on startup."""
        if not self.valves.VT_API_KEY:
            raise ValueError("VT_API_KEY environment variable is required")
        self.logger.info("VirusTotal Pipeline initialized successfully")

    async def on_shutdown(self):
        """Clean up resources."""
        pass

    def query_hash(self, file_hash: str) -> Dict:
        """Query VirusTotal for information about a specific file hash."""
        try:
            headers = {
                "accept": "application/json",
                "x-apikey": self.valves.VT_API_KEY
            }
            
            url = f"{self.valves.VT_BASE_URL}/files/{file_hash}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            if self.valves.ENABLE_DEBUG:
                self.logger.debug(f"VT Response: {json.dumps(response.json(), indent=2)}")
                
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error querying hash {file_hash}: {str(e)}")
            return {}

    def extract_ip_addresses(self, vt_response: Dict) -> List[Dict]:
        """Extract IP addresses from the VirusTotal response."""
        ip_addresses = []
        
        try:
            data = vt_response.get('data', {})
            attributes = data.get('attributes', {})
            
            # Check multiple potential locations for IP addresses
            # 1. Check contacted_ips
            contacted_ips = attributes.get('contacted_ips', [])
            for ip_data in contacted_ips:
                ip_info = {
                    'ip': ip_data.get('ip'),
                    'timestamp': ip_data.get('timestamp', 0),
                    'relationship': 'contacted',
                    'country': ip_data.get('country', 'unknown')
                }
                ip_addresses.append(ip_info)
            
            # 2. Check network communications
            network_traffic = attributes.get('network_traffic', {})
            if network_traffic:
                for connection in network_traffic.get('connections', []):
                    ip_info = {
                        'ip': connection.get('remote_ip'),
                        'timestamp': connection.get('timestamp', 0),
                        'relationship': 'network_traffic',
                        'country': 'unknown'
                    }
                    if ip_info['ip']:
                        ip_addresses.append(ip_info)
            
            # 3. Check behaviors section
            behaviors = attributes.get('behaviors', [])
            for behavior in behaviors:
                if 'network_events' in behavior:
                    for event in behavior['network_events']:
                        if 'ip' in event:
                            ip_info = {
                                'ip': event['ip'],
                                'timestamp': event.get('timestamp', 0),
                                'relationship': 'behavior_network',
                                'country': 'unknown'
                            }
                            ip_addresses.append(ip_info)
                            
        except Exception as e:
            self.logger.error(f"Error extracting IP addresses: {str(e)}")
            
        return ip_addresses

    def format_results(self, ip_addresses: List[Dict]) -> str:
        """Format the results for output."""
        output = []
        
        if ip_addresses:
            output.append(f"Found {len(ip_addresses)} IP addresses:")
            for ip_info in ip_addresses:
                output.append(f"\nIP: {ip_info['ip']}")
                if ip_info['timestamp']:
                    output.append(f"Timestamp: {datetime.fromtimestamp(ip_info['timestamp'])}")
                output.append(f"Relationship: {ip_info['relationship']}")
                output.append(f"Country: {ip_info['country']}")
        else:
            output.append("No IP addresses found in the response")
            
        return "\n".join(output)

    def pipe(self, prompt: str = None, **kwargs) -> Generator[str, None, None]:
        """Process input and return results."""
        if not prompt:
            yield "Please provide a file hash to analyze"
            return

        try:
            # Clean the hash input
            file_hash = prompt.strip()
            
            # Query VirusTotal
            response = self.query_hash(file_hash)
            
            if response:
                # Extract and format IP addresses
                ip_addresses = self.extract_ip_addresses(response)
                formatted_results = self.format_results(ip_addresses)
                
                if self.valves.ENABLE_DEBUG:
                    yield "Raw API Response:\n"
                    yield json.dumps(response, indent=2)
                    yield "\n\n"
                
                yield formatted_results
            else:
                yield f"No data found for hash: {file_hash}"

        except Exception as e:
            yield f"Error processing request: {str(e)}"

    def run(self, prompt: str, **kwargs) -> List[Dict[str, Any]]:
        """Run pipeline and return results."""
        results = list(self.pipe(prompt=prompt, **kwargs))
        if not results:
            return []
        return [{"text": "".join(results)}]
