import requests
import json
import re
from pydantic import BaseModel, Field
from typing import Optional, List, Callable, Awaitable, Dict, Any, Generator
import time
import aiohttp
import logging
import os

# --- Configure Logging ---
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VirusTotalValves(BaseModel):
    """
    Valve for API key used to connect to Virus Total.
    """
    virustotal_api_key: str = Field(
        default="", description="API Key for Virus Total"
    )

class Pipeline:  # Define the Pipeline class
    """
    Retrieves and displays VirusTotal reports for a given file hash.
    """
    def __init__(self):
        # Initialize valves using environment variables or defaults
        self.valves = VirusTotalValves(
            **{
                "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
            }
        )
        self.last_emit_time = 0
        self.emit_interval = 1.0
        self.enable_status_indicator = True
        self.citation = True

        self.pipe = self.get_virus_total_report_tool

    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

    def validate_api_key(self, api_key):
        """
        Performs basic validation on the VirusTotal API key.
        """
        logger.debug(f"Validating API key: {api_key}")
        if not api_key or len(api_key) != 64:
            logger.warning("Invalid API key format.")
            return False
        return True

    def validate_file_hash(self, file_hash):
        """
        Validates the format of a SHA-256 file hash.
        """
        logger.debug(f"Validating file hash: {file_hash}")
        if not file_hash or len(file_hash) != 64 or not re.match(r"^[a-f0-9]+$", file_hash, re.IGNORECASE):
            logger.warning("Invalid file hash format.")
            return False
        return True

    async def get_virustotal_report(self, file_hash, __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None):
        """
        Retrieves a VirusTotal report for a given file hash.
        """
        api_key = self.valves.virustotal_api_key
        logger.info(f"Using API key from valves: {api_key}")

        if not self.validate_api_key(api_key):
            if __event_emitter__:
                await self.emit_status(__event_emitter__, "error", "Invalid API key format.", True)
            return None

        if not self.validate_file_hash(file_hash):
            if __event_emitter__:
                await self.emit_status(__event_emitter__, "error", "Invalid file hash format", True)
            return None

        url = f"{self.VIRUSTOTAL_API_URL}{file_hash}"
        headers = {
            "x-apikey": api_key
        }

        logger.debug(f"Request URL: {url}")
        logger.debug(f"Request headers: {headers}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    report_data = await response.json()
                    logger.debug(f"VirusTotal API response: {report_data}")
                    return report_data

        except aiohttp.ClientResponseError as e:
            error_message = f"HTTP error fetching VirusTotal report: {e.status}, {e.message}"
            if __event_emitter__:
                await self.emit_status(__event_emitter__, "error", error_message, True)
            logger.error(error_message)
            return None
        except aiohttp.ClientError as e:
            error_message = f"Network error fetching VirusTotal report: {str(e)}"
            if __event_emitter__:
                await self.emit_status(__event_emitter__, "error", error_message, True)
            logger.error(error_message)
            return None
        except Exception as e:
            error_message = f"Unexpected error fetching VirusTotal report: {str(e)}"
            if __event_emitter__:
                await self.emit_status(__event_emitter__, "error", error_message, True)
            logger.error(error_message)
            return None

    def format_report_for_display(self, report):
        """
        Formats the VirusTotal report for display in the console (standalone use).
        """

        if report is None:
            logger.warning("No report data to format.")
            return "No report available."

        try:
            data = report['data']
            attributes = data['attributes']
            file_name = attributes.get('meaningful_name', attributes.get('names', [''])[0])
            last_analysis_stats = attributes['last_analysis_stats']
            scan_results = attributes['last_analysis_results']

            output = ""
            output += f"File name: {file_name}\n"
            output += f"File type: {attributes.get('type_description', 'Unknown')}\n"
            output += f"File size: {attributes.get('size', 'Unknown')} bytes\n"
            output += f"First seen: {attributes.get('first_submission_date', 'Unknown')}\n"
            output += f"Last analysis date: {attributes.get('last_analysis_date', 'Unknown')}\n"
            output += f"Detection ratio: {last_analysis_stats.get('malicious',0)}/{last_analysis_stats.get('total', 0)}\n"

            output += "\nScan results:\n"
            for engine, result in scan_results.items():
                category = result.get('category', 'Unknown')
                engine_name = result.get('engine_name', engine)
                engine_result = result.get('result', 'N/A')
                output += f"  {engine_name}: {category} ({engine_result})\n"

            logger.debug(f"Formatted report:\n{output}")
            return output

        except KeyError as e:
            error_message = f"Error parsing VirusTotal report: Missing key {e}"
            logger.error(error_message)
            return error_message

    def format_report_for_openwebui(self, report):
        """
        Formats the VirusTotal report as a JSON object for OpenWebUI.
        """
        if report is None:
            logger.warning("No report data to format for OpenWebUI.")
            return {"error": "No report available."}

        try:
            data = report['data']
            attributes = data['attributes']
            last_analysis_stats = attributes['last_analysis_stats']
            scan_results = attributes['last_analysis_results']

            formatted_results = []
            for engine, result in scan_results.items():
                formatted_results.append({
                    "engine": result.get('engine_name', engine),
                    "category": result.get('category', 'Unknown'),
                    "result": result.get('result', 'N/A')
                })

            formatted_report = {
                "file_name": attributes.get('meaningful_name', attributes.get('names', [''])[0]),
                "file_type": attributes.get('type_description', 'Unknown'),
                "file_size": attributes.get('size', 'Unknown'),
                "first_seen": attributes.get('first_submission_date', 'Unknown'),
                "last_analysis_date": attributes.get('last_analysis_date', 'Unknown'),
                "detection_ratio": f"{last_analysis_stats.get('malicious', 0)}/{last_analysis_stats.get('total', 0)}",
                "scan_results": formatted_results,
            }
            logger.debug(f"Formatted report for OpenWebUI: {formatted_report}")
            return formatted_report

        except KeyError as e:
            error_message = f"Error parsing VirusTotal report: Missing key {e}"
            logger.error(error_message)
            return {"error": error_message}

    async def emit_status(
        self,
        __event_emitter__: Callable[[dict], Awaitable[None]],
        level: str,
        message: str,
        done: bool,
    ):
        current_time = time.time()
        if (
            __event_emitter__
            and self.enable_status_indicator
            and (
                current_time - self.last_emit_time >= self.emit_interval or done
            )
        ):
            await __event_emitter__(
                {
                    "type": "status",
                    "data": {
                        "status": "complete" if done else "in_progress",
                        "level": level,
                        "description": message,
                        "done": done,
                    },
                }
            )
            self.last_emit_time = current_time
            
    async def get_virus_total_report_tool(
        self,
        file_hash: str,
        __event_emitter__: Callable[[dict], Awaitable[None]] = None,
    ) -> str:
        """
        Retrieves a formatted VirusTotal report for a given file hash.

        :param file_hash: The SHA-256 hash of the file to check.
        :return: A formatted string containing the VirusTotal report, or an error message.
        """
        logger.info(f"Getting VirusTotal report for file hash: {file_hash}")  # Info log
        if __event_emitter__:
            await self.emit_status(
                __event_emitter__, "info", "Starting Virus Total file report", False
            )

        report = await self.get_virustotal_report(file_hash, __event_emitter__)

        if report:
            formatted_report = self.format_report_for_display(report)
            if __event_emitter__:
                await self.emit_status(
                    __event_emitter__, "info", "Virus Total report complete", True
                )
            logger.info("VirusTotal report retrieval complete.")  # Info log
            return formatted_report
        else:
            if __event_emitter__:
                await self.emit_status(
                    __event_emitter__, "error", "Failed to retrieve Virus Total report", True
                )
            logger.error("Failed to retrieve VirusTotal report.")  # Error log
            return "Error: Failed to retrieve Virus Total report"

    async def run(
        self,
        file_hash: str,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Retrieves a formatted VirusTotal report for a given file hash.
        This is the main entry point for the pipeline.
        """
        logger.info(f"Getting VirusTotal report for file hash: {file_hash}")

        report = await self.get_virustotal_report(file_hash, None)

        if report:
            formatted_report = self.format_report_for_openwebui(report)
            logger.info("VirusTotal report retrieval complete.")
            return [formatted_report]
        else:
            logger.error("Failed to retrieve VirusTotal report.")
            return [{"error": "Failed to retrieve Virus Total report."}]

# Example usage (for testing outside of OpenWebUI):
if __name__ == "__main__":
    # You can optionally set the API key as an environment variable for testing
    # os.environ["VIRUSTOTAL_API_KEY"] = "YOUR_API_KEY"

    file_hash = input("Enter the file hash: ")
    pipeline_instance = Pipeline()  # Use the Pipeline class

    async def test_pipeline(file_hash):
        result = await pipeline_instance.run(file_hash)
        print(json.dumps(result, indent=2))

    import asyncio
    asyncio.run(test_pipeline(file_hash))
