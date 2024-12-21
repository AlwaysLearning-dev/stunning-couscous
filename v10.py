"""
title: VirusTotal Hash Analysis Pipeline
author: open-webui
date: 2024-12-20
version: 1.0
license: MIT
description: A pipeline for querying VirusTotal API and analyzing file hashes with LLM context
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
        LLM_MODEL_NAME: str
        LLM_BASE_URL: str
        ENABLE_CONTEXT: bool
        LOG_LEVEL: str

    def __init__(self):
        # Initialize valves with environment variables or defaults
        self.valves = self.Valves(
            **{
                "VT_API_KEY": os.getenv("VT_API_KEY", ""),
                "VT_BASE_URL": os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3"),
                "LLM_MODEL_NAME": os.getenv("LLAMA_MODEL_NAME", "llama3.2"),
                "LLM_BASE_URL": os.getenv("OLLAMA_BASE_URL", "http://ollama:11434"),
                "ENABLE_CONTEXT": os.getenv("ENABLE_CONTEXT", "true").lower() == "true",
                "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO")
            }
        )

        # Store last analysis results for context
        self.last_vt_data = None
        
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

    def looks_like_hash(self, text: str) -> bool:
        """Check if the input looks like a hash value."""
        text = text.strip()
        return len(text) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in text)

    def query_virustotal(self, file_hash: str) -> Dict:
        """Query VirusTotal API for file information."""
        try:
            headers = {
                "accept": "application/json",
                "x-apikey": self.valves.VT_API_KEY
            }
            
            url = f"{self.valves.VT_BASE_URL}/files/{file_hash}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            self.logger.debug(f"VT Response received for hash: {file_hash}")
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error querying VirusTotal: {str(e)}")
            return {}

    def get_context_from_vt_data(self, vt_data: Dict) -> str:
        """Create context string from VirusTotal data for LLM."""
        if not vt_data:
            return ""
        
        try:
            context = []
            data = vt_data.get('data', {})
            attributes = data.get('attributes', {})
            
            # Basic file information
            context.append("File Analysis Results:")
            context.append(f"Type: {attributes.get('type_description', 'Unknown')}")
            context.append(f"Size: {attributes.get('size', 'Unknown')} bytes")
            context.append(f"First Seen: {attributes.get('first_submission_date', 'Unknown')}")
            
            # Analysis stats
            stats = attributes.get('last_analysis_stats', {})
            context.append("\nDetection Statistics:")
            context.append(f"Malicious Detections: {stats.get('malicious', 0)}")
            context.append(f"Suspicious Detections: {stats.get('suspicious', 0)}")
            context.append(f"Clean Detections: {stats.get('undetected', 0)}")
            
            # Network connections
            if attributes.get('contacted_ips'):
                context.append("\nNetwork Connections:")
                for ip in attributes['contacted_ips']:
                    context.append(f"IP: {ip.get('ip', 'unknown')}")
                    context.append(f"Country: {ip.get('country', 'unknown')}")
            
            # Behaviors
            if attributes.get('behaviors'):
                context.append("\nObserved Behaviors:")
                for behavior in attributes['behaviors']:
                    if 'category' in behavior:
                        context.append(f"Category: {behavior['category']}")
                    if 'action' in behavior:
                        context.append(f"Action: {behavior['action']}")
            
            return "\n".join(context)
            
        except Exception as e:
            self.logger.error(f"Error creating context: {str(e)}")
            return "Error processing VirusTotal data"

    def create_llm_prompt(self, query: str, context: str) -> str:
        """Create a prompt for the LLM including VirusTotal context."""
        if context:
            return f"""Here is the VirusTotal analysis data for context:

{context}

Based on this VirusTotal analysis, please answer this question:
{query}"""
        return query

    def pipe(self, prompt: str = None, **kwargs) -> Generator[str, None, None]:
        """Process input and return results."""
        user_input = prompt or kwargs.get('user_message', '')
        if not user_input:
            yield "How can I help you? You can ask me any question or provide a file hash for analysis."
            return

        try:
            context = ""
            llm_prompt = user_input
            
            # Check if the input contains a hash
            if self.looks_like_hash(user_input):
                vt_response = self.query_virustotal(user_input.strip())
                if vt_response:
                    self.last_vt_data = vt_response
                    context = self.get_context_from_vt_data(vt_response)
                    llm_prompt = "Provide a brief summary of this file analysis."
            # If it's not a hash, check if we have context from a previous hash lookup
            elif self.last_vt_data:
                context = self.get_context_from_vt_data(self.last_vt_data)
            
            # If we have context, include it in the prompt
            if context:
                llm_prompt = self.create_llm_prompt(llm_prompt, context)

            # Send to LLM with context
            self.logger.debug(f"Sending prompt to LLM: {llm_prompt}")
            response = requests.post(
                url=f"{self.valves.LLM_BASE_URL}/api/generate",
                headers={"Content-Type": "application/json"},
                json={
                    "model": self.valves.LLM_MODEL_NAME,
                    "prompt": llm_prompt,
                    "stream": True
                }
            )
            
            self.logger.debug(f"LLM response status: {response.status_code}")
            
            if response.status_code != 200:
                self.logger.error(f"LLM API error: {response.text}")
                yield "Error communicating with LLM service"
                return
            
            try:
                for line in response.iter_lines(decode_unicode=True):
                    if line and line.strip():
                        try:
                            data = json.loads(line)
                            if "response" in data:
                                yield data["response"]
                            else:
                                self.logger.debug(f"Unexpected LLM response format: {data}")
                        except json.JSONDecodeError as e:
                            self.logger.error(f"Error parsing LLM response: {e}")
                            self.logger.debug(f"Problematic line: {line}")
            except Exception as e:
                self.logger.error(f"Error processing LLM stream: {e}")
                yield f"Error processing LLM response: {str(e)}"

        except Exception as e:
            self.logger.error(f"Error in pipe: {str(e)}")
            yield f"Error processing request: {str(e)}"

    def run(self, prompt: str, **kwargs) -> List[Dict[str, Any]]:
        """Run pipeline and return results."""
        results = list(self.pipe(prompt=prompt, **kwargs))
        if not results:
            return []
        return [{"text": "".join(results)}]
