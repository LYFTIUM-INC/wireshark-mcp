#!/usr/bin/env python3
"""
Async Long-Duration Packet Capture for Wireshark MCP
====================================================

This script enables 5+ minute packet captures that run in the background
and can be analyzed with MCP tools after completion.
"""

import asyncio
import os
import json
import tempfile
import time
from typing import Dict, Any, Optional
from pathlib import Path

class AsyncPacketCapture:
    """Async packet capture manager for long-duration captures"""
    
    def __init__(self):
        self.capture_dir = Path("/tmp/mcp_captures")
        self.capture_dir.mkdir(exist_ok=True)
        self.active_captures = {}
        
    async def start_long_capture(
        self,
        interface: str = "lo",
        duration: int = 300,  # 5 minutes default
        filter_expr: str = "",
        max_packets: int = 10000,
        capture_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Start a long-duration background capture"""
        
        if not capture_name:
            capture_name = f"capture_{int(time.time())}"
            
        pcap_file = self.capture_dir / f"{capture_name}.pcap"
        status_file = self.capture_dir / f"{capture_name}_status.json"
        
        # Build tcpdump command (uses capabilities, not sudo)
        cmd = [
            'timeout', str(duration),
            'tcpdump',
            '-i', interface,
            '-w', str(pcap_file),
            '-c', str(max_packets),
            '-q'  # Quiet mode
        ]
        
        if filter_expr:
            cmd.append(filter_expr)
            
        try:
            # Start background process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Store capture info
            capture_info = {
                "capture_name": capture_name,
                "interface": interface,
                "duration": duration,
                "filter": filter_expr,
                "max_packets": max_packets,
                "pcap_file": str(pcap_file),
                "status_file": str(status_file),
                "pid": process.pid,
                "start_time": time.time(),
                "status": "running"
            }
            
            self.active_captures[capture_name] = {
                "process": process,
                "info": capture_info
            }
            
            # Save status to file
            with open(status_file, 'w') as f:
                json.dump(capture_info, f, indent=2)
                
            # Start monitoring task
            asyncio.create_task(self._monitor_capture(capture_name))
            
            return {
                "status": "✅ Started",
                "capture_name": capture_name,
                "interface": interface,
                "duration": f"{duration} seconds",
                "filter": filter_expr,
                "max_packets": max_packets,
                "output_file": str(pcap_file),
                "status_file": str(status_file),
                "pid": process.pid,
                "note": "Capture running in background. Use check_capture() to monitor."
            }
            
        except Exception as e:
            return {
                "status": "❌ Failed",
                "error": str(e),
                "note": "Check that tcpdump has proper capabilities: cap_net_raw,cap_net_admin"
            }
    
    async def _monitor_capture(self, capture_name: str):
        """Monitor a running capture and update status"""
        if capture_name not in self.active_captures:
            return
            
        capture = self.active_captures[capture_name]
        process = capture["process"]
        info = capture["info"]
        
        try:
            # Wait for completion
            stdout, stderr = await process.communicate()
            
            # Update final status
            info["status"] = "completed" if process.returncode in [0, 124] else "failed"
            info["end_time"] = time.time()
            info["return_code"] = process.returncode
            info["stderr"] = stderr.decode() if stderr else ""
            
            # Get file size if successful
            pcap_file = Path(info["pcap_file"])
            if pcap_file.exists():
                info["file_size"] = pcap_file.stat().st_size
                info["packets_captured"] = await self._count_packets(pcap_file)
            
            # Update status file
            with open(info["status_file"], 'w') as f:
                json.dump(info, f, indent=2)
                
        except Exception as e:
            info["status"] = "error"
            info["error"] = str(e)
            info["end_time"] = time.time()
            
        finally:
            # Remove from active captures
            if capture_name in self.active_captures:
                del self.active_captures[capture_name]
    
    async def _count_packets(self, pcap_file: Path) -> int:
        """Count packets in PCAP file"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'tshark', '-r', str(pcap_file), '-q', '-z', 'io,stat,0',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                # Parse packet count from tshark output
                for line in stdout.decode().split('\n'):
                    if 'frames' in line.lower():
                        parts = line.split('|')
                        if len(parts) > 1:
                            try:
                                return int(parts[1].strip().split()[0])
                            except (ValueError, IndexError):
                                pass
        except Exception:
            pass
        return 0
    
    def check_capture(self, capture_name: str) -> Dict[str, Any]:
        """Check status of a running or completed capture"""
        status_file = self.capture_dir / f"{capture_name}_status.json"
        
        if not status_file.exists():
            return {
                "status": "❌ Not Found",
                "capture_name": capture_name,
                "note": "Capture not found or never started"
            }
            
        try:
            with open(status_file, 'r') as f:
                info = json.load(f)
                
            # Add runtime info
            if info["status"] == "running":
                runtime = time.time() - info["start_time"]
                info["runtime_seconds"] = runtime
                info["runtime_formatted"] = f"{runtime:.1f}s"
                
                # Check if process is still alive
                if capture_name in self.active_captures:
                    info["process_alive"] = True
                else:
                    info["process_alive"] = False
                    info["note"] = "Process may have completed, check file"
            
            return info
            
        except Exception as e:
            return {
                "status": "❌ Error",
                "error": str(e),
                "capture_name": capture_name
            }
    
    def list_captures(self) -> Dict[str, Any]:
        """List all captures (active and completed)"""
        captures = []
        
        # Check for status files
        for status_file in self.capture_dir.glob("*_status.json"):
            try:
                with open(status_file, 'r') as f:
                    info = json.load(f)
                    captures.append({
                        "name": info["capture_name"],
                        "status": info["status"],
                        "interface": info["interface"],
                        "duration": f"{info['duration']}s",
                        "file_size": info.get("file_size", "unknown"),
                        "packets": info.get("packets_captured", "unknown")
                    })
            except Exception as e:
                captures.append({
                    "name": status_file.stem.replace("_status", ""),
                    "status": "error",
                    "error": str(e)
                })
        
        return {
            "active_captures": len(self.active_captures),
            "total_captures": len(captures),
            "captures": captures,
            "capture_directory": str(self.capture_dir)
        }
    
    async def stop_capture(self, capture_name: str) -> Dict[str, Any]:
        """Stop a running capture"""
        if capture_name not in self.active_captures:
            return {
                "status": "❌ Not Found",
                "capture_name": capture_name,
                "note": "Capture not found or already stopped"
            }
            
        try:
            capture = self.active_captures[capture_name]
            process = capture["process"]
            
            # Terminate process gracefully
            process.terminate()
            
            # Wait for completion
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # Force kill if needed
                process.kill()
                await process.wait()
                
            return {
                "status": "✅ Stopped",
                "capture_name": capture_name,
                "note": "Capture stopped successfully"
            }
            
        except Exception as e:
            return {
                "status": "❌ Error",
                "error": str(e),
                "capture_name": capture_name
            }

# Global capture manager
capture_manager = AsyncPacketCapture()

async def start_5_minute_capture(
    interface: str = "lo",
    filter_ports: str = "port 3000 or port 8080 or port 7444"
) -> Dict[str, Any]:
    """Start a 5-minute capture on specified ports"""
    return await capture_manager.start_long_capture(
        interface=interface,
        duration=300,  # 5 minutes
        filter_expr=filter_ports,
        max_packets=50000,  # Allow more packets for long capture
        capture_name="five_minute_capture"
    )

async def start_background_capture(
    duration_minutes: int = 5,
    interface: str = "lo",
    filter_expr: str = ""
) -> Dict[str, Any]:
    """Start a background capture with custom parameters"""
    return await capture_manager.start_long_capture(
        interface=interface,
        duration=duration_minutes * 60,
        filter_expr=filter_expr,
        max_packets=duration_minutes * 10000,  # Scale packets with duration
        capture_name=f"background_{duration_minutes}min"
    )

# Test function
async def test_async_capture():
    """Test the async capture functionality"""
    print("🧪 Testing Async Long Capture")
    print("=" * 40)
    
    # Start a short test capture (30 seconds)
    result = await capture_manager.start_long_capture(
        interface="lo",
        duration=30,
        filter_expr="port 3000 or port 8080 or port 7444",
        max_packets=100,
        capture_name="test_capture"
    )
    
    print(json.dumps(result, indent=2))
    
    if result["status"] == "✅ Started":
        print("\n⏳ Waiting 5 seconds then checking status...")
        await asyncio.sleep(5)
        
        status = capture_manager.check_capture("test_capture")
        print(json.dumps(status, indent=2))
        
        print("\n📋 Listing all captures...")
        captures = capture_manager.list_captures()
        print(json.dumps(captures, indent=2))

if __name__ == "__main__":
    asyncio.run(test_async_capture())