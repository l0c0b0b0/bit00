import asyncio
import os

LOCK = asyncio.Lock()
SEMAPHORE = asyncio.Semaphore(int(os.getenv('CONCURRENT_SCANS')))
ACTIVE_PROCESS = set()
RUNNING_TASKS = []