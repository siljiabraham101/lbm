"""mDNS / ZeroConf discovery for LBM nodes."""
from __future__ import annotations

import socket
import asyncio
import logging
from typing import Optional, TYPE_CHECKING
from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser, AsyncServiceInfo

from .logging_config import get_logger

if TYPE_CHECKING:
    from .node import BatteryNode

logger = get_logger("lb.discovery")

LBM_SERVICE_TYPE = "_lbm._tcp.local."


class LBMServiceListener:
    """Listener for mDNS service events."""

    def __init__(self, node: "BatteryNode"):
        self.node = node

    def remove_service(self, zeroconf, type, name) -> None:
        pass

    def update_service(self, zeroconf, type, name) -> None:
        pass

    def add_service(self, zeroconf, type, name) -> None:
        # creating a task to process the service info
        asyncio.create_task(self._process_service(zeroconf, type, name))
        
    async def _process_service(self, zeroconf, type, name) -> None:
        try:
            info = AsyncServiceInfo(type, name)
            if not await info.async_request(zeroconf, 3000):
                return

            # Decode properties
            props = {}
            for k, v in info.properties.items():
                try:
                    if isinstance(k, bytes):
                        k = k.decode("utf-8")
                    if isinstance(v, bytes):
                        v = v.decode("utf-8")
                    props[k] = v
                except Exception:
                    continue

            node_id = props.get("node_id")
            if not node_id:
                return

            # Ignore self
            if node_id == self.node.node_id:
                return

            # Resolve address
            if not info.addresses:
                return
                
            # Prefer IPv4
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port

            logger.info(f"Discovered peer via mDNS: {node_id[:8]}... at {ip}:{port}")
            
            # Register peer
            await self.node.register_peer(ip, port, alias=f"mdns-{node_id[:6]}")
        except Exception as e:
            logger.debug(f"Error processing mDNS service {name}: {e}")


class DiscoveryService:
    """Manages mDNS registration and browsing using AsyncZeroconf."""

    def __init__(self, node: "BatteryNode", port: int):
        self.node = node
        self.port = port
        self.aio_zc: Optional[AsyncZeroconf] = None
        self.info: Optional[AsyncServiceInfo] = None
        self.browser: Optional[AsyncServiceBrowser] = None

    async def start(self) -> None:
        """Start mDNS registration and browsing."""
        if self.aio_zc:
            return

        logger.info("Starting mDNS discovery service...")
        try:
            self.aio_zc = AsyncZeroconf()
        except Exception as e:
            logger.error(f"Failed to initialize AsyncZeroconf: {e}")
            return

        # 1. Register Service
        ip = self._get_local_ip()
        if not ip:
            logger.warning("Could not determine local IP for mDNS")
            return

        # Unique service name
        service_name = f"lbm-{self.node.node_id[:12]}.{LBM_SERVICE_TYPE}"
        
        props = {
            "node_id": self.node.node_id,
            "version": "0.1.0",
            "sign_pub": self.node.keys.sign_pub_b64,
            "enc_pub": self.node.keys.enc_pub_b64,
        }

        self.info = AsyncServiceInfo(
            LBM_SERVICE_TYPE,
            service_name,
            addresses=[socket.inet_aton(ip)],
            port=self.port,
            properties=props,
        )

        try:
            await self.aio_zc.async_register_service(self.info)
            logger.info(f"Registered mDNS service: {service_name}")
        except Exception as e:
            logger.error(f"Failed to register mDNS service: {repr(e)}")

        # 2. Start Browser
        try:
            await self.aio_zc.async_add_service_listener(
                LBM_SERVICE_TYPE, 
                LBMServiceListener(self.node)
            )
        except Exception as e:
             logger.error(f"Failed to start browser: {e}")

    async def stop(self) -> None:
        """Stop mDNS service."""
        if self.aio_zc:
            logger.info("Stopping mDNS discovery...")
            try:
                await self.aio_zc.async_close()
            except Exception as e:
                logger.error(f"Error stopping mDNS: {e}")
            self.aio_zc = None
            self.browser = None

    def _get_local_ip(self) -> Optional[str]:
        """Best effort to get local LAN IP."""
        try:
            # We don't actually connect, just determine route
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
