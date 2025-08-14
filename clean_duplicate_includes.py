#!/usr/bin/env python3
"""
Clean up duplicate secure_log.h includes and ensure proper placement
"""

import os
import re

def clean_includes(content):
    """Clean up duplicate includes and ensure proper placement"""
    lines = content.split('\n')
    
    # Find all secure_log.h includes
    secure_log_includes = []
    other_lines = []
    
    for i, line in enumerate(lines):
        if re.match(r'\s*#include\s+["\'].*secure_log\.h["\']', line.strip()):
            secure_log_includes.append((i, line))
        else:
            other_lines.append((i, line))
    
    if len(secure_log_includes) <= 1:
        return content  # No duplicates
    
    print(f"Found {len(secure_log_includes)} secure_log.h includes")
    
    # Remove all secure_log includes
    new_lines = [line for i, line in other_lines]
    
    # Find the last include statement
    last_include_idx = -1
    for i, line in enumerate(new_lines):
        if re.match(r'\s*#include\s+', line.strip()):
            last_include_idx = i
    
    # Add single secure_log include after last include
    if last_include_idx >= 0:
        new_lines.insert(last_include_idx + 1, '#include "../../include/betanet/secure_log.h"')
    else:
        new_lines.insert(0, '#include "../../include/betanet/secure_log.h"')
    
    return '\n'.join(new_lines)

def fix_file(file_path):
    """Fix a single file by cleaning duplicate includes"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'secure_log.h' in content:
            print(f"Checking: {file_path}")
            new_content = clean_includes(content)
            
            if new_content != content:
                print(f"Fixed duplicates in: {file_path}")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                return True
            else:
                print(f"No changes needed: {file_path}")
        
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
