#!/usr/bin/env python3
"""
BetaNet Code Security Remediation Script
Systematically replaces unsafe C functions with secure alternatives across the codebase.
"""

import os
import re
import glob
from typing import Dict, List, Tuple

class SecurityRemediation:
    """Handles systematic security fixes for unsafe C code patterns"""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.files_modified = 0
        self.total_fixes = 0
        
        # Pattern definitions for unsafe functions and their secure replacements
        self.unsafe_patterns = {
            # Buffer overflow vulnerabilities
            r'\bstrcpy\s*\(\s*([^,]+),\s*([^)]+)\)': r'secure_strcpy(\1, sizeof(\1), \2)',
            r'\bstrcat\s*\(\s*([^,]+),\s*([^)]+)\)': r'secure_strcat(\1, sizeof(\1), \2)',
            r'\bsprintf\s*\(\s*([^,]+),\s*([^)]+)\)': r'secure_snprintf(\1, sizeof(\1), \2)',
            r'\bsnprintf\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)': r'secure_snprintf(\1, \2, \3)',
            
            # Memory operations that need bounds checking
            r'\bmemcpy\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)': r'secure_memcpy(\1, sizeof(\1), \2, \3)',
            r'\bmemset\s*\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)': r'secure_memset(\1, \2, \3)',
            
            # Dangerous input functions
            r'\bgets\s*\(\s*([^)]+)\)': r'/* SECURITY: gets() removed - use secure_readline() instead */',
            r'\bscanf\s*\(\s*': r'/* SECURITY: scanf() usage needs review - consider secure alternatives */',
            
            # Unsafe printf variants in production code (not in test files)
            r'\bprintf\s*\(\s*"([^"]*)"([^)]*)\)': lambda m: self._replace_printf(m),
        }
        
        # Files to include secure headers
        self.header_includes = [
            '#include "../../include/betanet/secure_utils.h"',
            '#include "../../include/betanet/secure_log.h"'
        ]
    
    def _replace_printf(self, match) -> str:
        """Replace printf with secure logging based on context"""
        format_str = match.group(1)
        args = match.group(2) if match.group(2) else ""
        
        # Determine log level based on format string content
        if any(keyword in format_str.lower() for keyword in ['error', 'fail', 'critical']):
            log_level = 'ERROR'
        elif any(keyword in format_str.lower() for keyword in ['warn', 'warning']):
            log_level = 'WARN'
        elif any(keyword in format_str.lower() for keyword in ['debug', 'trace']):
            log_level = 'DEBUG'
        else:
            log_level = 'INFO'
        
        # Extract component tag from format string
        tag = self._extract_component_tag(format_str)
        
        return f'BETANET_LOG_{log_level}({tag}, "{format_str}"{args})'
    
    def _extract_component_tag(self, format_str: str) -> str:
        """Extract appropriate log tag from format string"""
        format_lower = format_str.lower()
        
        if 'htx' in format_lower:
            return 'BETANET_LOG_TAG_HTX'
        elif 'noise' in format_lower:
            return 'BETANET_LOG_TAG_NOISE'
        elif 'path' in format_lower:
            return 'BETANET_LOG_TAG_PATH'
        elif 'scion' in format_lower:
            return 'BETANET_LOG_TAG_SCION'
        elif 'ticket' in format_lower:
            return 'BETANET_LOG_TAG_TICKET'
        elif 'calibration' in format_lower or 'calib' in format_lower:
            return 'BETANET_LOG_TAG_CALIB'
        elif 'http' in format_lower or 'h2' in format_lower:
            return 'BETANET_LOG_TAG_HTTP2'
        elif 'perf' in format_lower or 'performance' in format_lower:
            return 'BETANET_LOG_TAG_PERF'
        elif 'crypto' in format_lower or 'encrypt' in format_lower:
            return 'BETANET_LOG_TAG_CRYPTO'
        else:
            return 'BETANET_LOG_TAG_CORE'
    
    def process_file(self, file_path: str) -> bool:
        """Process a single file for security remediation"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            file_modified = False
            
            # Skip test files for printf replacement (they may need printf for assertion output)
            is_test_file = 'test' in file_path.lower() or '/tests/' in file_path
            
            # Apply security fixes
            for pattern, replacement in self.unsafe_patterns.items():
                if pattern.startswith(r'\bprintf') and is_test_file:
                    continue  # Skip printf replacement in test files
                
                if callable(replacement):
                    # Handle complex replacements with lambda functions
                    content = re.sub(pattern, replacement, content)
                else:
                    # Handle simple string replacements
                    old_content = content
                    content = re.sub(pattern, replacement, content)
                    if content != old_content:
                        file_modified = True
                        self.total_fixes += len(re.findall(pattern, old_content))
            
            # Add security headers if needed
            if file_modified and content != original_content:
                content = self._add_security_headers(content, file_path)
            
            # Write back modified content
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.files_modified += 1
                print(f"✓ Fixed security issues in: {file_path}")
                return True
                
        except Exception as e:
            print(f"✗ Error processing {file_path}: {e}")
            
        return False
    
    def _add_security_headers(self, content: str, file_path: str) -> str:
        """Add necessary security headers to a C file"""
        lines = content.split('\n')
        include_inserted = False
        
        # Find the last #include statement
        last_include_idx = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('#include'):
                last_include_idx = i
        
        # Insert security headers after the last include
        if last_include_idx >= 0:
            for header in reversed(self.header_includes):
                if header not in content:
                    lines.insert(last_include_idx + 1, header)
                    include_inserted = True
        
        return '\n'.join(lines)
    
    def process_project(self) -> None:
        """Process all C source files in the project"""
        print("BetaNet Security Remediation Tool")
        print("=================================")
        print(f"Processing project: {self.project_root}")
        print()
        
        # Find all C source files
        c_patterns = [
            os.path.join(self.project_root, "src", "**", "*.c"),
            os.path.join(self.project_root, "libbetanetc", "*.c"),
            os.path.join(self.project_root, "tests", "**", "*.c"),
        ]
        
        all_files = []
        for pattern in c_patterns:
            all_files.extend(glob.glob(pattern, recursive=True))
        
        print(f"Found {len(all_files)} C source files")
        print()
        
        # Process each file
        for file_path in sorted(all_files):
            self.process_file(file_path)
        
        # Print summary
        print()
        print("Security Remediation Summary")
        print("============================")
        print(f"Files processed: {len(all_files)}")
        print(f"Files modified: {self.files_modified}")
        print(f"Total security fixes applied: {self.total_fixes}")
        print()
        
        if self.files_modified > 0:
            print("✓ Security remediation completed successfully!")
            print("  Next steps:")
            print("  1. Implement secure_utils functions if not already done")
            print("  2. Implement secure_log functions if not already done")
            print("  3. Compile and test the project")
            print("  4. Run security analysis tools to verify fixes")
        else:
            print("No security issues found or all issues already fixed.")

def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = os.getcwd()
    
    if not os.path.exists(project_root):
        print(f"Error: Project directory '{project_root}' does not exist")
        sys.exit(1)
    
    remediation = SecurityRemediation(project_root)
    remediation.process_project()

if __name__ == "__main__":
    main()
