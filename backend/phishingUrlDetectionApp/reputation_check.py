import requests
import json
import os
import time
import sqlite3
import hashlib
import base64
from urllib.parse import urlparse
from datetime import datetime, timedelta

# Import our new modules
from .typosquatting import check_typosquatting, extract_domain_from_url, check_homograph_attack
from .external_apis import check_url_with_external_apis

class ReputationChecker:
    def __init__(self):
        # Initialize cache database
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'phishingUrlDetectionBackend', 'cache', 'reputation_cache.db')
        self.cache_dir = os.path.dirname(self.db_path)
        os.makedirs(self.cache_dir, exist_ok=True)
        self._init_cache_db()
        
        # API keys (in production, should be loaded from environment variables or secure storage)
        self.phishtank_api_key = os.environ.get('PHISHTANK_API_KEY', '')
        self.google_api_key = os.environ.get('GOOGLE_SAFEBROWSING_API_KEY', '')
        
        # PhishTank has a rate limit, so we'll cache results
        self.phishtank_cache_duration = 3600  # 1 hour in seconds
        
        # Load cached phishing domains on startup
        self.known_phishing_domains = self._load_cached_phishing_domains()
        
        # Load trusted domains for typosquatting checks
        self.trusted_domains = self._get_trusted_domains()
        
    def _init_cache_db(self):
        """Initialize the SQLite database for caching reputation data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table for URL reputation cache
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_reputation (
            url TEXT PRIMARY KEY,
            is_phishing INTEGER,
            source TEXT,
            timestamp INTEGER
        )
        ''')
        
        # Create table for domain reputation cache
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_reputation (
            domain TEXT PRIMARY KEY,
            is_phishing INTEGER,
            source TEXT,
            timestamp INTEGER
        )
        ''')
        
        # Create table for last update tracking
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS last_update (
            source TEXT PRIMARY KEY,
            timestamp INTEGER
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def _load_cached_phishing_domains(self):
        """Load known phishing domains from the cache"""
        known_domains = set()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all domains marked as phishing that are still valid (cached in the last 7 days)
        seven_days_ago = int(time.time()) - (7 * 24 * 60 * 60)
        cursor.execute('''
        SELECT domain FROM domain_reputation 
        WHERE is_phishing = 1 AND timestamp > ?
        ''', (seven_days_ago,))
        
        for row in cursor.fetchall():
            known_domains.add(row[0])
            
        conn.close()
        return known_domains
        
    def _get_trusted_domains(self):
        """Get list of trusted domains for typosquatting checks"""
        # Major search engines and email providers
        trusted_domains = [
            'google.com', 'gmail.com', 'youtube.com', 'yahoo.com', 'bing.com', 'baidu.com',
            'outlook.com', 'hotmail.com', 'protonmail.com', 'mail.com', 'zoho.com',
            
            # Social media
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com',
            'reddit.com', 'tumblr.com', 'tiktok.com', 'snapchat.com', 'whatsapp.com',
            
            # E-commerce
            'amazon.com', 'ebay.com', 'walmart.com', 'aliexpress.com', 'etsy.com',
            'shopify.com', 'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
            
            # Technology
            'microsoft.com', 'apple.com', 'ibm.com', 'oracle.com', 'intel.com',
            'amd.com', 'nvidia.com', 'cisco.com', 'dell.com', 'hp.com',
            
            # Cloud services
            'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com', 'digitalocean.com',
            'heroku.com', 'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
            
            # Financial
            'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
            'capitalone.com', 'americanexpress.com', 'visa.com', 'mastercard.com',
            
            # News and media
            'cnn.com', 'bbc.com', 'nytimes.com', 'wsj.com', 'reuters.com',
            'bloomberg.com', 'forbes.com', 'washingtonpost.com', 'theguardian.com',
            
            # Streaming services
            'netflix.com', 'hulu.com', 'disneyplus.com', 'spotify.com', 'apple.com/music',
            'youtube.com/music', 'soundcloud.com', 'twitch.tv', 'hbomax.com'
        ]
        
        return trusted_domains
        
    def check_url(self, url):
        """Check if a URL is a phishing site using multiple methods
        
        Returns:
            dict: Result with 'is_phishing' boolean and 'source' of determination
        """
        # Extract domain for domain-based checks
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Try cache first (both exact URL and domain)
        cache_result = self._check_cache(url, domain)
        if cache_result:
            return cache_result
            
        # Check trusted domains list (this is a local allow-list)
        if self._is_trusted_domain(domain):
            self._update_cache(url, domain, False, 'trusted_list')
            return {'is_phishing': False, 'source': 'trusted_list', 'confidence': 0.95}
        
        # Check known phishing domains set (in-memory cache)
        if domain in self.known_phishing_domains:
            return {'is_phishing': True, 'source': 'cached_phishing_list', 'confidence': 0.9}
        
        # NEW: Check for homograph attacks (Unicode tricks)
        if check_homograph_attack(domain):
            self._update_cache(url, domain, True, 'homograph_attack')
            return {'is_phishing': True, 'source': 'homograph_attack', 'confidence': 0.95}
        
        # NEW: Check for typosquatting
        typosquatting_result = check_typosquatting(domain, self.trusted_domains)
        if typosquatting_result and typosquatting_result['is_typosquatting']:
            self._update_cache(url, domain, True, 'typosquatting')
            return {
                'is_phishing': True, 
                'source': 'typosquatting', 
                'confidence': typosquatting_result['confidence'],
                'impersonated_domain': typosquatting_result['impersonated_domain']
            }
        
        # NEW: Check with external APIs (VirusTotal, IBM X-Force, Cloudflare)
        external_api_result = check_url_with_external_apis(url)
        if external_api_result and 'status' not in external_api_result:
            is_phishing = external_api_result.get('is_phishing', False)
            source = external_api_result.get('source', 'external_apis')
            confidence = external_api_result.get('confidence', 0.8)
            
            # Update cache with the result
            self._update_cache(url, domain, is_phishing, source)
            
            return {
                'is_phishing': is_phishing,
                'source': source,
                'confidence': confidence,
                'details': external_api_result.get('details', {})
            }
        
        # Try external APIs
        # 1. PhishTank API
        phishtank_result = self._check_phishtank(url)
        if phishtank_result['status'] == 'success':
            is_phishing = phishtank_result['is_phishing']
            self._update_cache(url, domain, is_phishing, 'phishtank')
            return {'is_phishing': is_phishing, 'source': 'phishtank', 'confidence': 0.9}
        
        # 2. Google Safe Browsing API
        safebrowsing_result = self._check_google_safebrowsing(url)
        if safebrowsing_result['status'] == 'success':
            is_phishing = safebrowsing_result['is_phishing']
            self._update_cache(url, domain, is_phishing, 'google_safebrowsing')
            return {'is_phishing': is_phishing, 'source': 'google_safebrowsing', 'confidence': 0.95}
        
        # If no definitive result from external sources, return None to indicate
        # that we should fall back to the ML model
        return None
    
    def _check_cache(self, url, domain):
        """Check if URL or domain is in the cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check URL cache first (exact match)
        cursor.execute('''
        SELECT is_phishing, source, timestamp FROM url_reputation WHERE url = ?
        ''', (url,))
        
        row = cursor.fetchone()
        if row:
            # Check if cache is still valid (24 hours)
            if int(time.time()) - row[2] < 24 * 60 * 60:
                conn.close()
                return {'is_phishing': bool(row[0]), 'source': f'cache_{row[1]}', 'confidence': 0.85}
        
        # Check domain cache
        cursor.execute('''
        SELECT is_phishing, source, timestamp FROM domain_reputation WHERE domain = ?
        ''', (domain,))
        
        row = cursor.fetchone()
        if row:
            # Check if cache is still valid (24 hours)
            if int(time.time()) - row[2] < 24 * 60 * 60:
                conn.close()
                return {'is_phishing': bool(row[0]), 'source': f'cache_{row[1]}', 'confidence': 0.8}
        
        conn.close()
        return None
    
    def _update_cache(self, url, domain, is_phishing, source):
        """Update cache with URL and domain reputation"""
        current_time = int(time.time())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update URL cache
        cursor.execute('''
        INSERT OR REPLACE INTO url_reputation (url, is_phishing, source, timestamp)
        VALUES (?, ?, ?, ?)
        ''', (url, 1 if is_phishing else 0, source, current_time))
        
        # Update domain cache
        cursor.execute('''
        INSERT OR REPLACE INTO domain_reputation (domain, is_phishing, source, timestamp)
        VALUES (?, ?, ?, ?)
        ''', (domain, 1 if is_phishing else 0, source, current_time))
        
        conn.commit()
        conn.close()
        
        # If phishing, add to in-memory set
        if is_phishing:
            self.known_phishing_domains.add(domain)
    
    def _is_trusted_domain(self, domain):
        """Check if domain is in the trusted list"""
        # Major search engines and email providers
        trusted_domains = self._get_trusted_domains()
        
        # Check for exact match or subdomain of trusted domain
        for trusted in trusted_domains:
            if domain == trusted or domain.endswith('.' + trusted):
                return True
                
        return False
    
    def _check_phishtank(self, url):
        """Check if a URL is in PhishTank database
        
        Args:
            url: The URL to check
            
        Returns:
            dict: Result with status and is_phishing boolean
        """
        if not self.phishtank_api_key:
            return {'status': 'error', 'message': 'PhishTank API key not configured'}
            
        try:
            # PhishTank API endpoint
            api_url = 'https://checkurl.phishtank.com/checkurl/'
            
            # Prepare request data
            data = {
                'url': url,
                'format': 'json',
                'app_key': self.phishtank_api_key
            }
            
            response = requests.post(api_url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if 'results' in result and 'in_database' in result['results']:
                    is_in_database = result['results']['in_database']
                    
                    if is_in_database:
                        is_phishing = result['results']['phish_detail_page'] is not None
                        return {'status': 'success', 'is_phishing': is_phishing}
                    else:
                        # URL not in PhishTank database
                        return {'status': 'success', 'is_phishing': False}
            
            return {'status': 'error', 'message': f'Error: {response.status_code}'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Exception: {str(e)}'}
    
    def _check_google_safebrowsing(self, url):
        """Check if a URL is in Google Safe Browsing database
        
        Args:
            url: The URL to check
            
        Returns:
            dict: Result with status and is_phishing boolean
        """
        if not self.google_api_key:
            return {'status': 'error', 'message': 'Google Safe Browsing API key not configured'}
            
        try:
            # Google Safe Browsing API endpoint
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}'
            
            # Prepare request data
            data = {
                'client': {
                    'clientId': 'phishing-url-detection',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(api_url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                # If matches found, URL is dangerous
                is_phishing = 'matches' in result and len(result['matches']) > 0
                
                return {'status': 'success', 'is_phishing': is_phishing}
            
            return {'status': 'error', 'message': f'Error: {response.status_code}'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Exception: {str(e)}'}
    
    def update_phishing_database(self):
        """Update the phishing database from external sources"""
        print("Updating phishing database...")
        
        # Update from PhishTank
        self._update_from_phishtank()
        
        # Update from OpenPhish
        self._update_from_openphish()
        
        # Update from URLhaus
        self._update_from_urlhaus()
        
        print("Phishing database update completed")
    
    def _update_from_phishtank(self):
        """Update phishing database from PhishTank"""
        last_update = self._get_last_update_time('phishtank')
        
        # Only update if it's been more than 6 hours
        if last_update and time.time() - last_update < 6 * 3600:
            print("PhishTank database is up to date")
            return
            
        try:
            print("Downloading PhishTank database...")
            url = 'https://data.phishtank.com/data/online-valid.json'
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                phishing_sites = response.json()
                
                # Process and store in database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for site in phishing_sites:
                    url = site.get('url', '')
                    if url:
                        try:
                            domain = extract_domain_from_url(url)
                            if domain:
                                self._update_cache(url, domain, True, 'phishtank')
                        except Exception as e:
                            print(f"Error processing URL {url}: {e}")
                
                conn.commit()
                conn.close()
                
                # Update last update time
                self._update_last_update_time('phishtank')
                print(f"Added {len(phishing_sites)} sites from PhishTank")
            else:
                print(f"Error downloading PhishTank database: {response.status_code}")
                
        except Exception as e:
            print(f"Error updating from PhishTank: {e}")
    
    def _update_from_openphish(self):
        """Update phishing database from OpenPhish"""
        # Similar implementation as PhishTank
        pass
    
    def _update_from_urlhaus(self):
        """Update phishing database from URLhaus"""
        # Similar implementation as PhishTank
        pass
    
    def _get_last_update_time(self, source):
        """Get the last update time for a source"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT timestamp FROM last_update WHERE source = ?
        ''', (source,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return row[0]
        return None
    
    def _update_last_update_time(self, source):
        """Update the last update time for a source"""
        current_time = int(time.time())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT OR REPLACE INTO last_update (source, timestamp)
        VALUES (?, ?)
        ''', (source, current_time))
        
        conn.commit()
        conn.close()


# Create a singleton instance
reputation_checker = ReputationChecker()

def check_url_reputation(url):
    """
    Check if a URL is a phishing site
    
    Args:
        url: The URL to check
        
    Returns:
        dict: Result with is_phishing boolean and source
    """
    return reputation_checker.check_url(url)

def update_phishing_database():
    """Update the phishing database from external sources"""
    reputation_checker.update_phishing_database() 