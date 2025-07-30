import threading
import time
import logging
from datetime import datetime, timedelta
import requests
import os
import sqlite3
from urllib.parse import urlparse

from .reputation_check import update_phishing_database

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PhishingDBUpdater")

class DatabaseUpdaterThread(threading.Thread):
    """Background thread to update phishing database periodically"""
    
    def __init__(self, update_interval=86400):  # Default: 24 hours
        super().__init__()
        self.daemon = True  # Daemon thread will automatically close when main thread ends
        self.update_interval = update_interval
        self.should_stop = threading.Event()
        
    def run(self):
        """Run the background task"""
        logger.info("Starting database updater thread")
        
        # First update immediately
        self._update_database()
        
        # Then update periodically
        while not self.should_stop.is_set():
            # Sleep for the interval, but check for stop signal every minute
            for _ in range(int(self.update_interval / 60)):
                if self.should_stop.is_set():
                    break
                time.sleep(60)
                
            if not self.should_stop.is_set():
                self._update_database()
        
        logger.info("Database updater thread stopped")
    
    def _update_database(self):
        """Run the database update with error handling"""
        try:
            logger.info("Starting phishing database update")
            result = update_phishing_database()
            if result['status'] == 'success':
                logger.info(f"Database update successful: {result['message']}")
            elif result['status'] == 'skipped':
                logger.info(f"Database update skipped: {result['message']}")
            else:
                logger.error(f"Database update failed: {result['message']}")
        except Exception as e:
            logger.error(f"Error in database updater: {str(e)}")
    
    def stop(self):
        """Stop the thread"""
        self.should_stop.set()

# Global updater thread instance
updater_thread = None

def start_database_updater():
    """Start the background database updater thread"""
    global updater_thread
    
    if updater_thread is None or not updater_thread.is_alive():
        updater_thread = DatabaseUpdaterThread()
        updater_thread.start()
        logger.info("Database updater thread started")
    else:
        logger.info("Database updater thread already running")

def stop_database_updater():
    """Stop the background database updater thread"""
    global updater_thread
    
    if updater_thread is not None and updater_thread.is_alive():
        updater_thread.stop()
        updater_thread.join(timeout=60)  # Wait up to 60 seconds for it to finish
        logger.info("Database updater thread stopped")

def phishing_database_updater():
    """Thread function to periodically update the phishing database"""
    from .reputation_check import update_phishing_database

    while True:
        try:
            # Log update attempt
            logging.info("Starting phishing database update")
            
            # Update phishing database from PhishTank
            result = update_phishing_database()
            
            if result['status'] == 'success':
                logging.info(f"Successfully updated phishing database: {result['message']}")
            elif result['status'] == 'skipped':
                logging.info(f"Phishing database update skipped: {result['message']}")
            else:
                logging.warning(f"Failed to update phishing database: {result['message']}")
            
            # Also check for newer sources - OpenPhish
            try:
                update_from_openphish()
            except Exception as e:
                logging.error(f"Error updating from OpenPhish: {str(e)}")
                
            # Update from URL Haus
            try:
                update_from_urlhaus()
            except Exception as e:
                logging.error(f"Error updating from URL Haus: {str(e)}")
                
        except Exception as e:
            logging.error(f"Error in phishing database updater: {str(e)}")
            
        # Wait for 12 hours before next update
        time.sleep(12 * 60 * 60)

def update_from_openphish():
    """Update phishing database from OpenPhish feed"""
    from .reputation_check import reputation_checker
    
    try:
        # OpenPhish free feed
        feed_url = "https://openphish.com/feed.txt"
        response = requests.get(feed_url, timeout=30)
        
        if response.status_code == 200:
            urls = response.text.strip().split('\n')
            domains_added = 0
            
            for phish_url in urls:
                try:
                    parsed_url = urlparse(phish_url)
                    domain = parsed_url.netloc.lower()
                    
                    if domain:
                        # Add to database and in-memory set
                        reputation_checker._update_cache(phish_url, domain, True, 'openphish')
                        domains_added += 1
                except Exception as e:
                    logging.error(f"Error processing OpenPhish URL {phish_url}: {str(e)}")
                    continue
            
            logging.info(f"Added {domains_added} domains from OpenPhish")
            return True
        else:
            logging.warning(f"OpenPhish feed returned status code {response.status_code}")
            return False
    except Exception as e:
        logging.error(f"Error fetching OpenPhish feed: {str(e)}")
        return False

def update_from_urlhaus():
    """Update phishing database from URLhaus feed"""
    from .reputation_check import reputation_checker
    
    try:
        # URLhaus CSV feed
        feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        response = requests.get(feed_url, timeout=30)
        
        if response.status_code == 200:
            # Skip the comment lines and header
            lines = response.text.strip().split('\n')
            data_lines = [line for line in lines if not line.startswith('#')]
            
            if len(data_lines) > 0:
                # Skip header row
                data_lines = data_lines[1:]
                
                domains_added = 0
                for line in data_lines:
                    try:
                        # CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
                        fields = line.split(',')
                        if len(fields) >= 3:
                            phish_url = fields[2].strip('"')
                            parsed_url = urlparse(phish_url)
                            domain = parsed_url.netloc.lower()
                            
                            if domain:
                                # Add to database and in-memory set
                                reputation_checker._update_cache(phish_url, domain, True, 'urlhaus')
                                domains_added += 1
                    except Exception as e:
                        logging.error(f"Error processing URLhaus line: {str(e)}")
                        continue
                
                logging.info(f"Added {domains_added} domains from URLhaus")
                return True
        else:
            logging.warning(f"URLhaus feed returned status code {response.status_code}")
            return False
    except Exception as e:
        logging.error(f"Error fetching URLhaus feed: {str(e)}")
        return False

def start_database_updater():
    """Start the database updater thread"""
    updater_thread = threading.Thread(target=phishing_database_updater, daemon=True)
    updater_thread.start()
    logging.info("Phishing database updater thread started")
    return updater_thread 