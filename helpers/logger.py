import os
from datetime import datetime
from typing import List

def log_command(basepath: str, tag: List[str], cmd: str) -> None:
    """Log command - saves to commands.log only"""
    logdir = os.path.join(basepath, 'logs')
    os.makedirs(logdir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d:%H.%M.%S')
    tag_str = ':'.join(tag)
    
    with open(os.path.join(logdir, 'commands.log'), 'a') as f:
        f.write(f"[*] [{timestamp}]:{tag_str}:{cmd}\n")

def log_pattern(basepath: str, tag: List[str], desc: str, match: str) -> None:
    """Log pattern - saves to patterns.log only"""
    logdir = os.path.join(basepath, 'logs')
    os.makedirs(logdir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d:%H.%M.%S')
    tag_str = ':'.join(tag)
    
    with open(os.path.join(logdir, 'patterns.log'), 'a') as f:
        f.write(f"[*] [{timestamp}]:{tag_str}:{desc}:{match}\n")

def log_error(basepath: str, tag: List[str], err: str) -> None:
    """Log error - saves to error.log only"""
    logdir = os.path.join(basepath, 'logs')
    os.makedirs(logdir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d:%H.%M.%S')
    tag_str = ':'.join(tag)
    
    with open(os.path.join(logdir, 'error.log'), 'a') as f:
        f.write(f"[-] [{timestamp}]:{tag_str}:Error:{err}\n")

def log_info(basepath: str, tag: List[str], message: str) -> None:
    """Log general info - saves to scanner.log only"""
    logdir = os.path.join(basepath, 'logs')
    os.makedirs(logdir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d:%H.%M.%S')
    tag_str = ':'.join(tag)
    
    with open(os.path.join(logdir, 'scanner.log'), 'a') as f:
        f.write(f"[*] [{timestamp}]:{tag_str}:{message}\n")