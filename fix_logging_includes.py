#!/usr/bin/env python3
"""
Fix missing secure_log.h includes in files that use BETANET_LOG_* functions
"""

import os
import re
import glob

def has_betanet_log_usage(content):
    """Check if the file uses BETANET_LOG_ functions"""
    return bool(re.search(r'BETANET_LOG_[A-Z_]+\s*\(', content))

def has_secure_log_include(content):
    """Check if the file already includes secure_log.h"""
    return bool(re.search(r'#include\s+["\'].*secure_log\.h["\']', content))

def add_secure_log_include(content):
    """Add secure_log.h include after the last include statement"""
    lines = content.split('\n')
    
    # Find the last include statement
    last_include_idx = -1
    for i, line in enumerate(lines):
        if re.match(r'\s*#include\s+', line.strip()):
            last_include_idx = i
    
    if last_include_idx == -1:
        # No includes found, add at the beginning
        lines.insert(0, '#include "../../include/betanet/secure_log.h"')
    else:
        # Add after the last include
        lines.insert(last_include_idx + 1, '#include "../../include/betanet/secure_log.h"')
    
    return '\n'.join(lines)

def fix_file(file_path):
    """Fix a single file by adding secure_log.h include if needed"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if has_betanet_log_usage(content) and not has_secure_log_include(content):
            print(f"Fixing: {file_path}")
            new_content = add_secure_log_include(content)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            return True
        else:
            print(f"Skipping: {file_path} (no BETANET_LOG usage or already has include)")
            return False
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to process all C files"""
    root_dir = "src"
    
    if not os.path.exists(root_dir):
        print(f"Source directory '{root_dir}' not found!")
        return
    
    # Find all C files
    c_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.c'):
                c_files.append(os.path.join(root, file))
    
    print(f"Found {len(c_files)} C files")
    
    fixed_count = 0
    for file_path in c_files:
        if fix_file(file_path):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()
