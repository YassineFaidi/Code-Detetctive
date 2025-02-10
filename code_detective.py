import re
import os
import sys
import subprocess
from typing import List, Dict, Any

class AdvancedCSecurityScanner:
    def __init__(self, verbose: bool = False):
        # Advanced regex patterns for security risks
        self.security_patterns = {
            'buffer_overflows': [
                # Unsafe functions
                r'\b(strcpy|strcat|sprintf|vsprintf)\b',
                # Potential unbounded string operations
                r'\bstrn?cpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)',
                # Dangerous input functions
                r'\bgets\s*\(',
                # Potential array out-of-bounds access
                r'\b[a-zA-Z_][a-zA-Z0-9_]*\[[^\]]+\]',
            ],
            'pointer_risks': [
                # Null pointer dereference
                r'\bNULL\s*->\s*',
                # Raw pointer arithmetic
                r'\*\s*\([^)]+\)\s*\+\s*[0-9]+',
                # Uninitialized pointers
                r'\b(char|int)\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*;',
            ],
            'memory_risks': [
                # Unsafe memory allocation
                r'\bmalloc\s*\([^)]+\)',
                # Variable-length stack allocation
                r'\balloca\s*\(',
                # Potential use-after-free
                r'\bfree\s*\([^)]+\)',
            ],
            'integer_risks': [
                # Potential integer overflow
                r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*',
                # Potential signed/unsigned comparison
                r'\(unsigned\)|unsigned\s+int',
            ],
            'format_string_risks': [
                # Potential format string vulnerabilities
                r'\bprintf\s*\([^)]+%[^)]+\)',
                r'\bsprintf\s*\([^)]+%[^)]+\)',
            ]
        }

        # Compile regex patterns
        self.compiled_patterns = {
            category: [re.compile(pattern) for pattern in patterns]
            for category, patterns in self.security_patterns.items()
        }

        self.verbose = verbose
        self.detailed_analysis = {}

    def scan_file(self, filepath: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Comprehensive security scan of a single C source file
        """
        risks = {category: [] for category in self.security_patterns.keys()}
        
        try:
            with open(filepath, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    # Check each category of risks
                    for category, patterns in self.compiled_patterns.items():
                        for pattern in patterns:
                            matches = pattern.findall(line)
                            if matches:
                                risks[category].append({
                                    'line': line_num,
                                    'content': line.strip(),
                                    'matches': matches,
                                    'risk_type': category
                                })
                
                # Advanced static analysis capabilities
                self._perform_advanced_checks(filepath, risks)
        
        except Exception as e:
            print(f"Error scanning {filepath}: {e}")
        
        return risks

    def _perform_advanced_checks(self, filepath: str, risks: Dict):
        """
        Perform additional advanced security checks
        """
        try:
            # Run external static analysis tools if available
            cppcheck_result = self._run_cppcheck(filepath)
            if cppcheck_result:
                risks['external_tool_findings'] = cppcheck_result
            
            # Analyze file for potential code injection vulnerabilities
            self._check_code_injection_risks(filepath, risks)
        
        except Exception as e:
            if self.verbose:
                print(f"Advanced analysis error: {e}")

    def _run_cppcheck(self, filepath: str) -> List[str]:
        """
        Run cppcheck for additional static analysis
        """
        try:
            result = subprocess.run(
                ['cppcheck', '--enable=all', '--quiet', filepath], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.stdout.splitlines()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

    def _check_code_injection_risks(self, filepath: str, risks: Dict):
        """
        Check for potential code injection vulnerabilities
        """
        with open(filepath, 'r') as file:
            content = file.read()
            
            # Check for potential shell command execution
            shell_risks = re.findall(r'\b(system|popen|exec)\s*\(', content)
            if shell_risks:
                risks['code_injection'] = [{
                    'risk': 'Potential shell command injection',
                    'functions': shell_risks
                }]

    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """
        Recursively scan all C/C++ source files in a directory
        """
        all_risks = {}
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.c', '.cpp', '.h', '.cc')):
                    filepath = os.path.join(root, file)
                    file_risks = self.scan_file(filepath)
                    
                    # Only add files with detected risks
                    if any(file_risks.values()):
                        all_risks[filepath] = file_risks
        
        return all_risks

    def generate_report(self, risks: Dict[str, Any]) -> None:
        """
        Generate a comprehensive security risk report
        """
        if not risks:
            print("No significant security risks detected.")
            return
        
        print("=== ADVANCED C/C++ SECURITY ANALYSIS REPORT ===")
        for filepath, file_risks in risks.items():
            print(f"\n[FILE] {filepath}")
            
            for category, risk_list in file_risks.items():
                if risk_list:
                    print(f"  {category.upper()} RISKS:")
                    for risk in risk_list:
                        print(f"    - Line {risk.get('line', 'N/A')}: {risk['content']}")
                        if 'matches' in risk:
                            print(f"      Specific Matches: {risk['matches']}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_c_security_scanner.py <directory_or_file>")
        sys.exit(1)
    
    path = sys.argv[1]
    scanner = AdvancedCSecurityScanner(verbose=True)
    
    if os.path.isdir(path):
        risks = scanner.scan_directory(path)
    elif os.path.isfile(path):
        risks = {path: scanner.scan_file(path)}
    else:
        print(f"Error: {path} is not a valid directory or file.")
        sys.exit(1)
    
    scanner.generate_report(risks)

if __name__ == "__main__":
    main()