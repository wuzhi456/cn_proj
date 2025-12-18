import struct
import pickle
from typing import Tuple, List
import sys
import os
import logging

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 现在可以正确导入utils模块
from utils.simsocket import AddressType, SimSocket

BUF_SIZE: int = 1400
HEADER_FMT: str = "!BBHIIB"  # 增加1字节的flags字段
HEADER_LEN: int = struct.calcsize(HEADER_FMT)
FLAG_LAST_PACKET = 0x01  # 最后一个包的标志
# 包类型常量
PKG_WHOHAS: int = 0
PKG_IHAVE: int = 1  
PKG_GET: int = 2
PKG_DATA: int = 3
PKG_ACK: int = 4
PKG_DENIED: int = 5

def build_packet(pkg_type: int, seq: int = 0, ack: int = 0, data: bytes = b"", flags: int = 0) -> bytes:
    """构建数据包"""
    plen = HEADER_LEN + len(data)
    header = struct.pack(HEADER_FMT, pkg_type, HEADER_LEN, plen, seq, ack, flags)
    return header + data

def parse_packet(pkt: bytes) -> Tuple[int, int, int, int, int, int, bytes]:
    """解析数据包"""
    if len(pkt) < HEADER_LEN:
        raise ValueError("Packet too short")
        
    pkg_type, hlen, plen, seq, ack, flags = struct.unpack(HEADER_FMT, pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:plen] if plen > HEADER_LEN else b""
    
    return pkg_type, hlen, plen, seq, ack, flags, data

def send_whohas(sock: SimSocket, chunk_hashes: List[bytes], peer_addrs: List[AddressType]) -> None:
    """向所有指定peer发送WHOHAS包"""
    data = pickle.dumps(chunk_hashes)
    packet = build_packet(PKG_WHOHAS, data=data, flags=0)
    logging.info(f"=== DEBUG: Sending WHOHAS to {len(peer_addrs)} peers ===")
    for peer_addr in peer_addrs:
        sock.sendto(packet, peer_addr)
        logging.debug(f"Sent WHOHAS to {peer_addr} for {len(chunk_hashes)} chunks")

def send_ihave(sock: SimSocket, peer_addr: AddressType, available_hashes: List[bytes]) -> None:
    """发送IHAVE包回复"""
    data = pickle.dumps(available_hashes)
    packet = build_packet(PKG_IHAVE, data=data, flags=0)
    sock.sendto(packet, peer_addr)

def send_get(sock: SimSocket, peer_addr: AddressType, chunk_hash: bytes) -> None:
    """发送GET包请求特定chunk"""
    logging.info(f"=== DEBUG: send_get START ===")
    logging.info(f"DEBUG: Sending GET to {peer_addr} for chunk {chunk_hash.hex()[:16]}...")
    
    packet = build_packet(PKG_GET, data=chunk_hash, flags=0)
    sock.sendto(packet, peer_addr)
    
    logging.info("=== DEBUG: send_get END ===")

def send_data(sock: SimSocket, peer_addr: AddressType, seq_num: int, data: bytes, is_last: bool = False) -> None:
    """发送DATA包，支持标记最后一个包"""
    flags = FLAG_LAST_PACKET if is_last else 0
    packet = build_packet(PKG_DATA, seq=seq_num, data=data, flags=flags)
    sock.sendto(packet, peer_addr)
    # 移除详细日志以减少输出，只在重要事件时记录
    if is_last or seq_num % 50 == 1:  # 每50个包记录一次开始
        logging.debug(f"Sent DATA packet to {peer_addr}, seq={seq_num}, is_last={is_last}, size={len(data)}")

def send_ack(sock: SimSocket, peer_addr: AddressType, ack_num: int) -> None:
    """发送ACK包"""
    packet = build_packet(PKG_ACK, ack=ack_num, flags=0)
    sock.sendto(packet, peer_addr)

def send_denied(sock: SimSocket, peer_addr: AddressType) -> None:
    """发送DENIED包"""
    packet = build_packet(PKG_DENIED, flags=0)
    sock.sendto(packet, peer_addr)