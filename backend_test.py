#!/usr/bin/env python3
"""
CyberSec Assistant Backend API Tests
Comprehensive testing of all FastAPI endpoints
"""

import requests
import json
import sys
from datetime import datetime
from typing import Dict, Any

class CyberSecBackendTester:
    def __init__(self, base_url="http://localhost:8001"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        result = {
            "name": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status} - {name}: {details}")

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int = 200, data: Dict[str, Any] = None, timeout: int = 10):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {'Content-Type': 'application/json'}
        
        try:
            print(f"\n🔍 Testing {name}...")
            print(f"   URL: {url}")
            
            start_time = datetime.now()
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=timeout)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            
            success = response.status_code == expected_status
            
            details = f"Status: {response.status_code} (expected {expected_status}), Time: {response_time:.2f}s"
            
            if success:
                try:
                    response_data = response.json()
                    details += f", Response keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Non-dict response'}"
                except:
                    details += ", Response: Non-JSON"
            else:
                details += f", Error: {response.text[:200]}"
            
            self.log_test(name, success, details)
            
            return success, response.json() if success and response.content else {}
            
        except requests.exceptions.Timeout:
            self.log_test(name, False, f"Timeout after {timeout}s")
            return False, {}
        except requests.exceptions.ConnectionError:
            self.log_test(name, False, "Connection error - server may be down")
            return False, {}
        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root endpoint"""
        return self.run_test("Root Endpoint", "GET", "/")

    def test_health_check(self):
        """Test health check endpoint"""
        return self.run_test("Health Check", "GET", "/api/health")

    def test_system_info(self):
        """Test system info endpoint"""
        return self.run_test("System Info", "GET", "/api/system/info")

    def test_get_config(self):
        """Test get configuration"""
        return self.run_test("Get Configuration", "GET", "/api/config")

    def test_update_config(self):
        """Test update configuration"""
        test_config = {
            "key": "test_setting",
            "value": "test_value",
            "description": "Test configuration setting"
        }
        return self.run_test("Update Configuration", "POST", "/api/config", 200, test_config)

    def test_get_scans(self):
        """Test get scans endpoint"""
        return self.run_test("Get Scans", "GET", "/api/scans")

    def test_create_scan(self):
        """Test create scan endpoint"""
        test_scan = {
            "scan_type": "port_scan",
            "target": "127.0.0.1",
            "status": "pending",
            "results": {"ports": [22, 80, 443]}
        }
        return self.run_test("Create Scan", "POST", "/api/scans", 200, test_scan)

    def test_tools_status(self):
        """Test tools status endpoint"""
        return self.run_test("Tools Status", "GET", "/api/tools/status")

    def test_get_logs(self):
        """Test get logs endpoint"""
        return self.run_test("Get Logs", "GET", "/api/logs")

    def test_get_logs_with_limit(self):
        """Test get logs with limit parameter"""
        return self.run_test("Get Logs (Limited)", "GET", "/api/logs?lines=50")

    # Brute Force Module Tests
    def test_bruteforce_health(self):
        """Test brute force health endpoint"""
        return self.run_test("Brute Force Health", "GET", "/api/bruteforce/health")

    def test_bruteforce_supported_protocols(self):
        """Test supported protocols endpoint"""
        return self.run_test("Supported Protocols", "GET", "/api/bruteforce/supported_protocols")

    def test_bruteforce_profiles(self):
        """Test brute force profiles endpoint"""
        return self.run_test("Brute Force Profiles", "GET", "/api/bruteforce/profiles")

    def test_bruteforce_wordlist_generation(self):
        """Test wordlist generation"""
        wordlist_request = {
            "generation_type": "common",
            "limit": 100
        }
        return self.run_test("Wordlist Generation", "POST", "/api/bruteforce/wordlists/generate", 200, wordlist_request)

    def test_bruteforce_hash_cracking(self):
        """Test hash cracking with MD5 hash of 'test'"""
        hash_request = {
            "hash_value": "098f6bcd4621d373cade4e832627b4f6",  # MD5 of "test"
            "hash_type": "md5",
            "custom_wordlist": ["test", "password", "admin", "123456"],
            "max_attempts": 1000
        }
        return self.run_test("Hash Cracking", "POST", "/api/bruteforce/hash/crack", 200, hash_request)

    def test_bruteforce_attacks_list(self):
        """Test list active attacks"""
        return self.run_test("List Active Attacks", "GET", "/api/bruteforce/attacks")

    def test_bruteforce_statistics(self):
        """Test brute force statistics"""
        return self.run_test("Brute Force Statistics", "GET", "/api/bruteforce/statistics")

    def test_bruteforce_wordlists_list(self):
        """Test list available wordlists"""
        return self.run_test("List Wordlists", "GET", "/api/bruteforce/wordlists")

    # Vulnerability Scanner Module Tests
    def test_vulnerability_health(self):
        """Test vulnerability scanner health endpoint"""
        return self.run_test("Vulnerability Scanner Health", "GET", "/api/vulnerability/health")

    def test_vulnerability_database_stats(self):
        """Test vulnerability database statistics"""
        return self.run_test("Vulnerability Database Stats", "GET", "/api/vulnerability/database/stats")

    def test_vulnerability_scan_list(self):
        """Test list vulnerability scans"""
        return self.run_test("List Vulnerability Scans", "GET", "/api/vulnerability/scan/list")

    def test_vulnerability_cve_search(self):
        """Test CVE search functionality"""
        search_request = {
            "service_name": "apache",
            "version": "2.4",
            "severity_filter": "HIGH",
            "limit": 10
        }
        return self.run_test("CVE Search", "POST", "/api/vulnerability/cve/search", 200, search_request)

    # Configuration Analysis Module Tests
    def test_configuration_health(self):
        """Test configuration analyzer health endpoint"""
        return self.run_test("Configuration Analyzer Health", "GET", "/api/configuration/health")

    def test_configuration_frameworks(self):
        """Test get compliance frameworks"""
        return self.run_test("Get Compliance Frameworks", "GET", "/api/configuration/frameworks")

    def test_configuration_scan_list(self):
        """Test list configuration scans"""
        return self.run_test("List Configuration Scans", "GET", "/api/configuration/scan/list")

    # Web Vulnerability Scanner Module Tests
    def test_web_vulnerability_health(self):
        """Test web vulnerability scanner health endpoint"""
        return self.run_test("Web Vulnerability Scanner Health", "GET", "/api/web-vulnerability/health")

    def test_web_vulnerability_scan_list(self):
        """Test list web vulnerability scans"""
        return self.run_test("List Web Vulnerability Scans", "GET", "/api/web-vulnerability/scan/list")

    def test_owasp_categories(self):
        """Test get OWASP categories"""
        return self.run_test("Get OWASP Categories", "GET", "/api/web-vulnerability/owasp/categories")

    # Forensics Module Tests
    def test_forensics_dashboard_overview(self):
        """Test forensics dashboard overview endpoint"""
        return self.run_test("Forensics Dashboard Overview", "GET", "/api/forensics/dashboard/overview")

    def test_forensics_logs_analyses(self):
        """Test get forensics log analyses"""
        return self.run_test("Forensics Log Analyses", "GET", "/api/forensics/logs/analyses")

    def test_forensics_files_analyses(self):
        """Test get forensics file analyses"""
        return self.run_test("Forensics File Analyses", "GET", "/api/forensics/files/analyses")

    def test_forensics_memory_analyses(self):
        """Test get forensics memory analyses"""
        return self.run_test("Forensics Memory Analyses", "GET", "/api/forensics/memory/analyses")

    def test_forensics_network_analyses(self):
        """Test get forensics network analyses"""
        return self.run_test("Forensics Network Analyses", "GET", "/api/forensics/network/analyses")

    def test_forensics_health(self):
        """Test forensics health endpoint"""
        return self.run_test("Forensics Health", "GET", "/api/forensics/health")

    def test_forensics_info(self):
        """Test forensics info endpoint"""
        return self.run_test("Forensics Info", "GET", "/api/forensics/info")

    def test_forensics_threat_intelligence(self):
        """Test forensics threat intelligence dashboard"""
        return self.run_test("Forensics Threat Intelligence", "GET", "/api/forensics/dashboard/threat-intelligence")

    def test_forensics_reports_cases(self):
        """Test forensics reports cases list"""
        return self.run_test("Forensics Reports Cases", "GET", "/api/forensics/reports/cases")

    # Stealth Control Module Tests (New)
    def test_stealth_control_status(self):
        """Test stealth control status endpoint"""
        return self.run_test("Stealth Control Status", "GET", "/api/stealth-control/status")

    def test_stealth_control_test_tor_connection(self):
        """Test Tor connection test endpoint"""
        return self.run_test("Test Tor Connection", "POST", "/api/stealth-control/test-tor-connection")

    # Proxy Configuration Module Tests (NEW - Priority for testing)
    def test_proxy_config_status(self):
        """Test proxy configuration status endpoint"""
        return self.run_test("Proxy Config Status", "GET", "/api/proxy-config/status")

    def test_proxy_config_get_config(self):
        """Test get proxy configuration"""
        return self.run_test("Get Proxy Config", "GET", "/api/proxy-config/config")

    def test_proxy_config_tor_config(self):
        """Test get Tor configuration"""
        return self.run_test("Get Tor Config", "GET", "/api/proxy-config/config/tor")

    def test_proxy_config_tor_update(self):
        """Test update Tor configuration"""
        tor_update = {
            "enabled": True,
            "auto_start": True,
            "use_as_primary": False
        }
        return self.run_test("Update Tor Config", "POST", "/api/proxy-config/config/tor/update", 200, tor_update)

    def test_proxy_config_general_update(self):
        """Test update general proxy configuration"""
        general_update = {
            "use_external_proxies": True,
            "stealth_level": 7,
            "auto_rotate_proxies": True
        }
        return self.run_test("Update General Config", "POST", "/api/proxy-config/config/general/update", 200, general_update)

    def test_proxy_config_external_proxies_config(self):
        """Test get external proxies configuration"""
        return self.run_test("Get External Proxies Config", "GET", "/api/proxy-config/config/external-proxies")

    def test_proxy_config_external_proxies_update(self):
        """Test update external proxies configuration"""
        external_update = {
            "enabled": True,
            "auto_test_proxies": True,
            "minimum_quality_score": 0.8,
            "test_timeout": 15
        }
        return self.run_test("Update External Proxies Config", "POST", "/api/proxy-config/config/external-proxies/update", 200, external_update)

    def test_proxy_config_proxies_list(self):
        """Test get proxy list"""
        return self.run_test("Get Proxy List", "GET", "/api/proxy-config/proxies/list")

    def test_proxy_config_add_proxy(self):
        """Test add external proxy"""
        proxy_add = {
            "proxy_url": "http://test.proxy.com:8080"
        }
        return self.run_test("Add Proxy", "POST", "/api/proxy-config/proxies/add", 200, proxy_add)

    def test_proxy_config_remove_proxy(self):
        """Test remove external proxy"""
        proxy_remove = {
            "proxy_url": "http://test.proxy.com:8080"
        }
        return self.run_test("Remove Proxy", "POST", "/api/proxy-config/proxies/remove", 200, proxy_remove)

    def test_proxy_config_tor_status(self):
        """Test Tor installation status"""
        return self.run_test("Tor Status", "GET", "/api/proxy-config/tor/status")

    def test_proxy_config_tor_install(self):
        """Test Tor installation (background task)"""
        return self.run_test("Tor Install", "POST", "/api/proxy-config/tor/install")

    def test_proxy_config_reset(self):
        """Test reset configuration to defaults"""
        return self.run_test("Reset Config", "POST", "/api/proxy-config/config/reset")

    def test_proxy_config_validate(self):
        """Test validate current configuration"""
        return self.run_test("Validate Config", "GET", "/api/proxy-config/validate")

    def test_proxy_config_help(self):
        """Test get configuration help"""
        return self.run_test("Get Config Help", "GET", "/api/proxy-config/help")

    def test_proxy_config_file_content(self):
        """Test get config file content"""
        return self.run_test("Get Config File Content", "GET", "/api/proxy-config/config/file-content")

    def test_performance(self):
        """Test API performance"""
        print(f"\n🚀 Performance Testing...")
        
        # Test multiple rapid requests
        performance_results = []
        for i in range(5):
            start_time = datetime.now()
            success, _ = self.run_test(f"Performance Test {i+1}", "GET", "/api/health", timeout=5)
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            performance_results.append(response_time)
            
            if not success:
                self.log_test("Performance Test", False, f"Failed on request {i+1}")
                return False
        
        avg_time = sum(performance_results) / len(performance_results)
        max_time = max(performance_results)
        
        # Performance criteria: average < 2s, max < 5s
        performance_ok = avg_time < 2.0 and max_time < 5.0
        
        details = f"Avg: {avg_time:.2f}s, Max: {max_time:.2f}s, All times: {[f'{t:.2f}s' for t in performance_results]}"
        self.log_test("Performance Test", performance_ok, details)
        
        return performance_ok

    def test_error_handling(self):
        """Test error handling"""
        print(f"\n🛡️ Error Handling Tests...")
        
        # Test non-existent endpoint
        success, _ = self.run_test("Non-existent Endpoint", "GET", "/api/nonexistent", 404)
        
        # Test invalid JSON in POST
        try:
            url = f"{self.base_url}/api/config"
            response = requests.post(url, data="invalid json", headers={'Content-Type': 'application/json'}, timeout=10)
            error_handled = response.status_code in [400, 422]  # Bad request or validation error
            self.log_test("Invalid JSON Handling", error_handled, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Invalid JSON Handling", False, f"Exception: {str(e)}")

    def run_all_tests(self):
        """Run all backend tests"""
        print("=" * 80)
        print("🛡️ CyberSec Assistant Backend API Tests")
        print("=" * 80)
        print(f"Testing backend at: {self.base_url}")
        print(f"Started at: {datetime.now().isoformat()}")
        print()

        # Core API Tests
        print("📡 Core API Endpoints:")
        self.test_root_endpoint()
        self.test_health_check()
        self.test_system_info()
        
        print("\n⚙️ Configuration Tests:")
        self.test_get_config()
        self.test_update_config()
        
        print("\n🔍 Scan Management Tests:")
        self.test_get_scans()
        self.test_create_scan()
        
        print("\n🛠️ Tools and Logs Tests:")
        self.test_tools_status()
        self.test_get_logs()
        self.test_get_logs_with_limit()
        
        print("\n🔨 Brute Force Module Tests:")
        self.test_bruteforce_health()
        self.test_bruteforce_supported_protocols()
        self.test_bruteforce_profiles()
        self.test_bruteforce_wordlist_generation()
        self.test_bruteforce_hash_cracking()
        self.test_bruteforce_attacks_list()
        self.test_bruteforce_statistics()
        self.test_bruteforce_wordlists_list()
        
        print("\n🛡️ Vulnerability Scanner Module Tests:")
        self.test_vulnerability_health()
        self.test_vulnerability_database_stats()
        self.test_vulnerability_scan_list()
        self.test_vulnerability_cve_search()
        
        print("\n⚙️ Configuration Analysis Module Tests:")
        self.test_configuration_health()
        self.test_configuration_frameworks()
        self.test_configuration_scan_list()
        
        print("\n🌐 Web Vulnerability Scanner Module Tests:")
        self.test_web_vulnerability_health()
        self.test_web_vulnerability_scan_list()
        self.test_owasp_categories()
        
        print("\n🔬 Forensics Module Tests:")
        self.test_forensics_dashboard_overview()
        self.test_forensics_logs_analyses()
        self.test_forensics_files_analyses()
        self.test_forensics_memory_analyses()
        self.test_forensics_network_analyses()
        self.test_forensics_health()
        self.test_forensics_info()
        self.test_forensics_threat_intelligence()
        self.test_forensics_reports_cases()
        
        print("\n🕵️ Stealth Control Module Tests:")
        self.test_stealth_control_status()
        self.test_stealth_control_test_tor_connection()
        
        print("\n🌐 Proxy Configuration Module Tests (PRIORITY):")
        self.test_proxy_config_status()
        self.test_proxy_config_get_config()
        self.test_proxy_config_tor_config()
        self.test_proxy_config_tor_status()
        self.test_proxy_config_proxies_list()
        self.test_proxy_config_external_proxies_config()
        self.test_proxy_config_help()
        self.test_proxy_config_validate()
        self.test_proxy_config_file_content()
        
        # Configuration update tests
        self.test_proxy_config_tor_update()
        self.test_proxy_config_general_update()
        self.test_proxy_config_external_proxies_update()
        
        # Proxy management tests
        self.test_proxy_config_add_proxy()
        self.test_proxy_config_remove_proxy()
        
        # Advanced tests
        self.test_proxy_config_tor_install()
        self.test_proxy_config_reset()
        
        # Performance Tests
        self.test_performance()
        
        # Error Handling Tests
        self.test_error_handling()
        
        # Final Report
        self.print_final_report()

    def print_final_report(self):
        """Print final test report"""
        print("\n" + "=" * 80)
        print("📊 FINAL TEST REPORT")
        print("=" * 80)
        
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        
        print(f"Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("🎉 EXCELLENT - Backend is working well!")
        elif success_rate >= 75:
            print("✅ GOOD - Backend is mostly functional")
        elif success_rate >= 50:
            print("⚠️ FAIR - Backend has some issues")
        else:
            print("❌ POOR - Backend has significant issues")
        
        # Show failed tests
        failed_tests = [test for test in self.test_results if not test['success']]
        if failed_tests:
            print(f"\n❌ Failed Tests ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"   - {test['name']}: {test['details']}")
        
        print(f"\nCompleted at: {datetime.now().isoformat()}")
        print("=" * 80)
        
        return success_rate >= 75  # Return True if tests are mostly passing

def main():
    """Main test execution"""
    tester = CyberSecBackendTester()
    
    try:
        success = tester.run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())