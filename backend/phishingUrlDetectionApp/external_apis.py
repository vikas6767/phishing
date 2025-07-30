"""
External APIs integration module for the phishing URL detection app.
This module provides functions to check URLs against VirusTotal, Cloudflare, and IBM X-Force Exchange.
"""

import os
import time
import json
import hashlib
import base64
import requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse, quote


class ExternalApiChecker:
    def __init__(self):
        """Initialize the external API checker with API keys from environment variables."""
        self.virustotal_api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        self.cloudflare_api_key = os.environ.get('CLOUDFLARE_API_KEY', '')
        self.cloudflare_email = os.environ.get('CLOUDFLARE_EMAIL', '')
        self.xforce_api_key = os.environ.get('IBM_XFORCE_API_KEY', '')
        self.xforce_api_password = os.environ.get('IBM_XFORCE_API_PASSWORD', '')
    
    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against VirusTotal.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with results including is_phishing boolean and confidence score
        """
        if not self.virustotal_api_key:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            # URL ID must be base64 encoded and URL safe
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "attributes" in data["data"]:
                    attributes = data["data"]["attributes"]
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    
                    # Count security vendors that flagged as malicious
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    suspicious_count = last_analysis_stats.get("suspicious", 0)
                    total_engines = sum(last_analysis_stats.values())
                    
                    if total_engines == 0:
                        return {'status': 'error', 'message': 'No scan results available'}
                    
                    # Calculate risk percentage
                    risk_percent = ((malicious_count + suspicious_count) / total_engines) * 100
                    
                    return {
                        'status': 'success',
                        'is_phishing': risk_percent >= 5,  # Consider phishing if 5% or more engines flag it
                        'confidence': min(risk_percent / 10, 0.95),  # Normalize to max 0.95 confidence
                        'malicious_detections': malicious_count,
                        'suspicious_detections': suspicious_count,
                        'total_engines': total_engines,
                        'source': 'virustotal'
                    }
                
            # Handle URL not found in VirusTotal
            if response.status_code == 404:
                # Submit for scanning
                scan_url = "https://www.virustotal.com/api/v3/urls"
                payload = {"url": url}
                scan_response = requests.post(scan_url, headers=headers, data=payload, timeout=10)
                
                if scan_response.status_code == 200:
                    return {
                        'status': 'pending',
                        'message': 'URL submitted for scanning',
                        'source': 'virustotal'
                    }
            
            return {'status': 'error', 'message': f"Error: {response.status_code}"}
            
        except Exception as e:
            return {'status': 'error', 'message': f"Exception: {str(e)}"}

    def check_cloudflare(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against Cloudflare Security APIs.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with results including is_phishing boolean and confidence score
        """
        if not self.cloudflare_api_key or not self.cloudflare_email:
            return {'status': 'error', 'message': 'Cloudflare API credentials not configured'}
        
        try:
            # Parse the domain from the URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            headers = {
                "X-Auth-Email": self.cloudflare_email,
                "X-Auth-Key": self.cloudflare_api_key,
                "Content-Type": "application/json"
            }
            
            # Use Cloudflare's Security Insights API (this is a simplified example)
            response = requests.get(
                f"https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?mode=block&configuration_target=ip&configuration_value={domain}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if there are any security rules for this domain
                if data.get('success') and len(data.get('result', [])) > 0:
                    return {
                        'status': 'success',
                        'is_phishing': True,
                        'confidence': 0.8,
                        'message': 'Domain is blocked by Cloudflare security rules',
                        'source': 'cloudflare'
                    }
                else:
                    return {
                        'status': 'success',
                        'is_phishing': False,
                        'confidence': 0.6,
                        'message': 'Domain not found in Cloudflare block lists',
                        'source': 'cloudflare'
                    }
            
            return {
                'status': 'error',
                'message': f"Error: {response.status_code}",
                'source': 'cloudflare'
            }
                
        except Exception as e:
            return {'status': 'error', 'message': f"Exception: {str(e)}", 'source': 'cloudflare'}
    
    def check_xforce(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against IBM X-Force Exchange.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with results including is_phishing boolean and confidence score
        """
        if not self.xforce_api_key or not self.xforce_api_password:
            return {'status': 'error', 'message': 'IBM X-Force API credentials not configured'}
        
        try:
            auth_string = f"{self.xforce_api_key}:{self.xforce_api_password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            
            headers = {
                "Authorization": f"Basic {encoded_auth}",
                "Accept": "application/json"
            }
            
            # URL needs to be URL-encoded for the API
            encoded_url = quote(url, safe='')
            
            response = requests.get(
                f"https://api.xforce.ibmcloud.com/url/{encoded_url}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract risk score
                risk_score = data.get('result', {}).get('score', 0)
                
                # IBM X-Force score interpretation (0-10 scale)
                # High scores indicate higher risk
                is_phishing = risk_score >= 7
                
                return {
                    'status': 'success',
                    'is_phishing': is_phishing,
                    'confidence': risk_score / 10.0,  # Normalize to 0-1 scale
                    'risk_score': risk_score,
                    'categories': data.get('result', {}).get('cats', {}),
                    'source': 'xforce'
                }
            
            return {
                'status': 'error',
                'message': f"Error: {response.status_code}",
                'source': 'xforce'
            }
                
        except Exception as e:
            return {'status': 'error', 'message': f"Exception: {str(e)}", 'source': 'xforce'}
    
    def check_all_apis(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against all configured external APIs.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with combined results and the most definitive result
        """
        results = {}
        
        # Check VirusTotal first if configured
        if self.virustotal_api_key:
            vt_result = self.check_virustotal(url)
            results['virustotal'] = vt_result
            
            # If we get a definitive result, use that
            if vt_result.get('status') == 'success' and vt_result.get('confidence', 0) > 0.7:
                return {
                    'is_phishing': vt_result.get('is_phishing', False),
                    'confidence': vt_result.get('confidence', 0),
                    'source': 'virustotal',
                    'details': results
                }
        
        # Check IBM X-Force if configured
        if self.xforce_api_key and self.xforce_api_password:
            xforce_result = self.check_xforce(url)
            results['xforce'] = xforce_result
            
            # If we get a definitive result, use that
            if xforce_result.get('status') == 'success' and xforce_result.get('confidence', 0) > 0.7:
                return {
                    'is_phishing': xforce_result.get('is_phishing', False),
                    'confidence': xforce_result.get('confidence', 0),
                    'source': 'xforce',
                    'details': results
                }
        
        # Check Cloudflare last if configured
        if self.cloudflare_api_key and self.cloudflare_email:
            cf_result = self.check_cloudflare(url)
            results['cloudflare'] = cf_result
        
        # Analyze all results to determine final verdict
        phishing_votes = 0
        safe_votes = 0
        total_confidence = 0
        api_count = 0
        
        for api_name, result in results.items():
            if result.get('status') == 'success':
                api_count += 1
                confidence = result.get('confidence', 0.5)
                
                if result.get('is_phishing', False):
                    phishing_votes += confidence
                else:
                    safe_votes += confidence
                
                total_confidence += confidence
        
        # Make final determination
        if api_count == 0:
            return {'status': 'error', 'message': 'No API results available'}
        
        is_phishing = phishing_votes > safe_votes
        
        # Calculate weighted confidence
        confidence = phishing_votes / total_confidence if is_phishing else safe_votes / total_confidence
        
        return {
            'is_phishing': is_phishing,
            'confidence': min(confidence, 0.95),  # Cap at 0.95 confidence
            'source': 'combined_apis',
            'details': results
        }


# Create a singleton instance
external_api_checker = ExternalApiChecker()

def check_url_with_external_apis(url: str) -> Dict[str, Any]:
    """
    Check a URL against all configured external APIs.
    
    Args:
        url: The URL to check
        
    Returns:
        Dict with combined results
    """
    return external_api_checker.check_all_apis(url) 