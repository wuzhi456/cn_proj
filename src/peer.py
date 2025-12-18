import sys
import select
import struct
import socket
import hashlib
import argparse
import pickle
import os
import logging
import time
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional

# 添加项目根目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from utils import simsocket
from utils.simsocket import AddressType
from utils.peer_context import PeerContext

from src.packet_utils import *
from src.peer_state import PeerState,TransferSession

"""
This is CS305 project skeleton code. Please refer to the example files -
  example/dump_receiver.py and
  example/dump_sender.py 
- to learn how to play with this skeleton.

The sample code is for reference only.
The given function is only one possible design, you are not required to follow it strictly.
We allow you to use better code design that conforms to best practices.
But ensure that your program's entry point is `peer.py` .
"""

BUF_SIZE: int = 1400

HEADER_FMT: str = "!BBHIIB"  # 增加1字节的flags字段
HEADER_LEN: int = struct.calcsize(HEADER_FMT)
FLAG_LAST_PACKET = 0x01  # 最后一个包的标志

class DownloadManager:
    """
    Enhanced download manager that supports multiple sources and crash recovery.
    """
    def __init__(self):
        self.needed_chunks: Set[bytes] = set()  # All chunks that need to be downloaded
        self.downloaded_chunks: Dict[bytes, bytes] = {}  # {chunk_hash: chunk_data}
        self.chunk_sources: Dict[bytes, Set[AddressType]] = defaultdict(set)  # Available peers for each chunk
        
        self.active_download: Optional[bytes] = None  # 当前正在下载的chunk（一个peer一次只能下载一个chunk）
        
        self.waiting_queue: Dict[AddressType, List[bytes]] = defaultdict(list)  # 每个peer的等待队列
        self.chunk_to_peer_map: Dict[bytes, AddressType] = {}  # chunk分配的peer
        self.peer_busy: Set[AddressType] = set()  # 忙碌的peers
        
        self.peer_last_activity: Dict[AddressType, float] = {}
        self.chunk_progress: Dict[bytes, Set[int]] = defaultdict(set)
        self.chunk_active_peers: Dict[bytes, Set[AddressType]] = defaultdict(set)

        # 下载尝试记录
        self.chunk_attempts: Dict[bytes, int] = defaultdict(int)
        self.max_attempts = 5
        
        self.suspected_peers: Dict[AddressType, float] = {}
        self.peer_retry_delay = 5.0
        
        self.output_file: Optional[str] = None
        self.is_active: bool = False

        logging.info(f"📊 DOWNLOAD MANAGER INIT: max_attempts={self.max_attempts}")
    
    def start_download(self, chunk_hashes: List[bytes], output_file: str) -> None:
        """Start a new download task"""
        self.needed_chunks.update(chunk_hashes)
        self.output_file = output_file
        self.is_active = True
        logging.debug(f"Download started: {len(chunk_hashes)} chunks -> {output_file}")
    
    def on_ihave_received(self, from_addr: AddressType, available_hashes: List[bytes]) -> None:
        """Process IHAVE response - update chunk source information"""
        for chunk_hash in available_hashes:
            if chunk_hash in self.needed_chunks:
                self.chunk_sources[chunk_hash].add(from_addr)
                logging.debug(f"Peer {from_addr} has chunk {chunk_hash.hex()[:16]}...")
    
    def schedule_downloads(self, sock: simsocket.SimSocket) -> None:
        """调度下载 - 一次只能有一个活跃下载，其他chunks排队等待"""
        logging.info("=== DEBUG: schedule_downloads START ===")
        active_hash = self.active_download.hex()[:16] if self.active_download else None
        logging.info(f"🔄 SCHEDULE: needed={len(self.needed_chunks)} active={active_hash} downloaded={len(self.downloaded_chunks)}")

        current_time = time.time()
        
        # 1. 清理可疑peer
        for peer_addr, suspect_time in list(self.suspected_peers.items()):
            if current_time - suspect_time > self.peer_retry_delay:
                del self.suspected_peers[peer_addr]
                logging.debug(f"Cleared suspicion for peer {peer_addr}")
        
        # 2. 如果有活跃下载，不需要调度新的
        if self.active_download is not None:
            logging.info(f"Already have active download: {self.active_download.hex()[:16]}...")
            
            # 检查活跃下载是否超时或失败
            if self._check_active_download_timeout():
                logging.warning(f"Active download timeout, will retry")
                self._handle_download_failure(sock, self.active_download)
            
            logging.info("=== DEBUG: schedule_downloads END (has active download) ===")
            return
        
        # 3. 选择下一个要下载的chunk
        for chunk_hash in list(self.needed_chunks):
            # 跳过已完成的
            if chunk_hash in self.downloaded_chunks:
                self.needed_chunks.discard(chunk_hash)
                continue
            
            # 检查尝试次数
            if self.chunk_attempts.get(chunk_hash, 0) >= self.max_attempts:
                logging.error(f"Max attempts reached for chunk {chunk_hash.hex()[:16]}")
                self.needed_chunks.discard(chunk_hash)
                continue
            
            # 获取可用peers
            available_peers = list(self.chunk_sources.get(chunk_hash, set()))
            if not available_peers:
                logging.debug(f"No known peers for chunk {chunk_hash.hex()[:16]}")
                continue
            
            # 选择最佳peer
            selected_peer = None
            for peer_addr in available_peers:
                if peer_addr in self.suspected_peers:
                    if current_time - self.suspected_peers[peer_addr] < self.peer_retry_delay:
                        continue
                
                # 如果peer忙，加入等待队列
                if peer_addr in self.peer_busy:
                    if chunk_hash not in self.waiting_queue[peer_addr]:
                        self.waiting_queue[peer_addr].append(chunk_hash)
                        logging.info(f"Added chunk {chunk_hash.hex()[:16]} to queue of busy peer {peer_addr}")
                    continue
                
                selected_peer = peer_addr
                break
            
            if selected_peer:
                # 开始下载这个chunk
                self._start_download_from_peer(sock, chunk_hash, selected_peer)
                break
            else:
                logging.debug(f"No available peer for chunk {chunk_hash.hex()[:16]}")
        
        # 4. 记录调度结果
        logging.info(f"📊 调度结果: active={self.active_download.hex()[:16] if self.active_download else None}")
        logging.info(f"      等待队列: {sum(len(q) for q in self.waiting_queue.values())} chunks")
        logging.info("=== DEBUG: schedule_downloads END ===")

    def _start_download_from_peer(self, sock: simsocket.SimSocket, chunk_hash: bytes, peer_addr: AddressType) -> None:
        """开始从指定peer下载chunk"""
        current_attempt = self.chunk_attempts.get(chunk_hash, 0) + 1
        logging.info(f"🎯 START DOWNLOAD [{current_attempt}/{self.max_attempts}] chunk={chunk_hash.hex()[:16]} peer={peer_addr}")
        
        # 记录尝试次数
        self.chunk_attempts[chunk_hash] = current_attempt
        
        # 设置活跃下载
        self.active_download = chunk_hash
        
        # 标记peer忙碌
        self.peer_busy.add(peer_addr)
        self.chunk_to_peer_map[chunk_hash] = peer_addr
        
        self.peer_last_activity[peer_addr] = time.time()
        self.chunk_active_peers[chunk_hash].add(peer_addr)

        # 创建下载会话
        try:
            # 清理可能的旧会话
            if sock.peer_state.get_download_session(peer_addr):
                logging.warning(f"Cleaning up old session for peer {peer_addr}")
                sock.peer_state.remove_download_session(peer_addr)
            
            session = sock.peer_state.start_download_session(peer_addr, chunk_hash)
            
            # 发送GET请求
            logging.info(f"Sending GET to {peer_addr} for chunk {chunk_hash.hex()[:16]}")
            send_get(sock, peer_addr, chunk_hash)
            
            logging.info(f"✅ Started download: chunk={chunk_hash.hex()[:16]} from {peer_addr}")
            
        except Exception as e:
            logging.error(f"Error starting download: {e}")
            # 清理状态
            self._cleanup_failed_download(chunk_hash, peer_addr)
    
    def on_chunk_received(self, sock: simsocket.SimSocket, chunk_hash: bytes, chunk_data: bytes) -> None:
        """处理下载完成的chunk - 修正active_download检查"""
        try:
            logging.info(f"=== on_chunk_received START: chunk {chunk_hash.hex()[:16]} ===")
        
            # 验证hash
            computed_hash = hashlib.sha1(chunk_data).digest()
            if computed_hash != chunk_hash:
                logging.error(f"Chunk hash verification failed for {chunk_hash.hex()[:16]}")
                return
        
            # 检查是否在需要下载的列表中
            if chunk_hash not in self.needed_chunks:
                logging.debug(f"Received chunk {chunk_hash.hex()[:16]} not in needed list")
                return
        
            # 保存chunk
            chunk_hash_hex = chunk_hash.hex()
            self.downloaded_chunks[chunk_hash_hex] = chunk_data
        
            # 从needed_chunks中移除
            self.needed_chunks.discard(chunk_hash)
        
            # 清理相关状态
            self._cleanup_completed_download(chunk_hash)
        
            logging.info(f"✅ Chunk downloaded: {chunk_hash_hex[:16]} "
                        f"({len(self.downloaded_chunks)} downloaded, {len(self.needed_chunks)} remaining)")
        
            # 检查是否全部完成
            if not self.needed_chunks:
                logging.info("🎉 All chunks downloaded! Saving result...")
                self._save_download_result()
            else:
                # 重新调度下一个下载
                logging.info(f"Chunk completed, {len(self.needed_chunks)} chunks remaining. Will schedule next download.")
                time.sleep(0.1)  # 等待100ms确保状态稳定
                self.schedule_downloads(sock)
        
            logging.info("=== on_chunk_received END ===")
        
        except Exception as e:
            logging.error(f"Error in on_chunk_received: {e}")

    def _cleanup_completed_download(self, chunk_hash: bytes) -> None:
        """清理完成下载后的状态"""
        logging.info(f"🔧 CLEANUP for chunk {chunk_hash.hex()[:16]}")
    
        # 1. 从needed_chunks中移除
        self.needed_chunks.discard(chunk_hash)
    
        # 2. 先记录旧的active_download
        old_active = self.active_download
    
        # 3. 清除活跃下载
        self.active_download = None
    
        # 4. 获取对应的peer
        peer_addr = self.chunk_to_peer_map.get(chunk_hash)
    
        # 5. 释放peer
        if peer_addr:
            self.peer_busy.discard(peer_addr)
            logging.info(f"Peer {peer_addr} freed")
    
        # 6. 清理映射
        self.chunk_to_peer_map.pop(chunk_hash, None)
    
        # 7. 清理其他状态
        self.chunk_active_peers.pop(chunk_hash, None)
        self.chunk_progress.pop(chunk_hash, None)
        self.chunk_attempts.pop(chunk_hash, None)
    
        logging.info(f"✅ Cleanup complete for chunk {chunk_hash.hex()[:16]}, "
                    f"was active={old_active.hex()[:16] if old_active else None}")

    def _cleanup_failed_download(self, chunk_hash: bytes, peer_addr: Optional[AddressType]) -> None:
        """清理失败下载的状态"""
        # 清除活跃下载
        if self.active_download == chunk_hash:
            self.active_download = None
        
        # 释放peer
        if peer_addr:
            self.peer_busy.discard(peer_addr)
        
        # 清理映射
        self.chunk_to_peer_map.pop(chunk_hash, None)
        
        # 从等待队列中移除
        for queue in self.waiting_queue.values():
            if chunk_hash in queue:
                queue.remove(chunk_hash)
        
        logging.info(f"Cleaned up failed download for chunk {chunk_hash.hex()[:16]}")
    
    def on_download_failed(self, chunk_hash: bytes, peer_addr: AddressType) -> None:
        """处理下载失败"""
        # 移除失败的peer
        if chunk_hash in self.chunk_active_peers:
            self.chunk_active_peers[chunk_hash].discard(peer_addr)
    
        # 释放peer
        self.peer_busy.discard(peer_addr)
        self.chunk_to_peer_map.pop(chunk_hash, None)
    
        # 清理等待队列
        if peer_addr in self.peer_queue and chunk_hash in self.peer_queue[peer_addr]:
            self.peer_queue[peer_addr].remove(chunk_hash)
    
        # 如果没有活跃peer，处理失败
        if not self.chunk_active_peers.get(chunk_hash):
            self.pending_gets.discard(chunk_hash)
        
            if self.chunk_attempts.get(chunk_hash, 0) < self.max_attempts:
                logging.info(f"Download failed, will retry chunk {chunk_hash.hex()[:16]}")
            else:
                logging.error(f"Permanently failed for chunk {chunk_hash.hex()[:16]}")
                self.needed_chunks.discard(chunk_hash)

    def _save_download_result(self) -> None:
        """Save downloaded chunks to output file"""
        if self.output_file:
            try:
                with open(self.output_file, 'wb') as f:
                    pickle.dump(self.downloaded_chunks, f)
                logging.info(f"Download completed: {self.output_file}")
                self.is_active = False
            except Exception as e:
                logging.error(f"Error saving download result: {e}")

    def on_data_received(self, from_addr: AddressType, chunk_hash: bytes, seq: int, data: bytes, is_last: bool) -> None:
        """Handle received data - 简化版本，只记录peer活动"""
        try:
            # 更新peer活动时间
            self.peer_last_activity[from_addr] = time.time()
        
            # 记录数据包进度
            self.chunk_progress[chunk_hash].add(seq)
        
            # 如果是当前活跃下载的chunk，记录活动
            if self.active_download == chunk_hash:
                logging.debug(f"Received packet {seq} for active download chunk {chunk_hash.hex()[:16]} from {from_addr}")
        
        except Exception as e:
            logging.error(f"Error in on_data_received: {e}")

    def on_peer_crash(self, sock: simsocket.SimSocket, chunk_hash: bytes, crashed_peer: AddressType) -> None:
        """处理peer崩溃事件"""
        current_time = time.time()
        
        logging.info(f"💥 CRASH DETECTED: peer={crashed_peer} chunk={chunk_hash.hex()[:16]}")
        
        # 标记peer可疑
        self.suspected_peers[crashed_peer] = current_time
        
        # 如果崩溃的peer正在下载活跃chunk
        if self.active_download == chunk_hash:
            self._handle_download_failure(sock, chunk_hash)
        else:
            # 从等待队列中移除这个peer的所有chunks
            if crashed_peer in self.waiting_queue:
                for waiting_chunk in list(self.waiting_queue[crashed_peer]):
                    logging.info(f"Removing chunk {waiting_chunk.hex()[:16]} from queue of crashed peer")
                self.waiting_queue.pop(crashed_peer, None)
            
            # 清理映射
            for ch, addr in list(self.chunk_to_peer_map.items()):
                if addr == crashed_peer:
                    self.chunk_to_peer_map.pop(ch, None)
        
        # 释放peer
        self.peer_busy.discard(crashed_peer)
        
        # 重新调度
        self.schedule_downloads(sock)

    def mark_peer_suspected(self, sock: simsocket.SimSocket, chunk_hash: bytes, peer_addr: AddressType) -> None:
        """标记peer可能有问题，立即检查是否需要恢复"""
        current_time = time.time()
        
        logging.info(f"⚠️ Marking peer {peer_addr} as suspected for chunk {chunk_hash.hex()[:16]}...")
        
        # 记录怀疑时间
        self.suspected_peers[peer_addr] = current_time
        
        # 从这个chunk的活跃peer中移除
        if chunk_hash in self.chunk_active_peers:
            self.chunk_active_peers[chunk_hash].discard(peer_addr)
        
        # 更新peer最后活动时间
        self.peer_last_activity[peer_addr] = current_time
        
        # 释放忙碌的peer
        self.peer_busy.discard(peer_addr)
        
        # 从队列中移除这个chunk
        if peer_addr in self.peer_queue and chunk_hash in self.peer_queue[peer_addr]:
            self.peer_queue[peer_addr].remove(chunk_hash)
        
        # 如果没有其他活跃peer，立即尝试恢复
        active_peers = self.chunk_active_peers.get(chunk_hash, set())
        if not active_peers:
            logging.info(f"🔍 No active peers for chunk {chunk_hash.hex()[:16]}..., checking for recovery")
            
            # 清除pending_gets，允许重新调度
            self.pending_gets.discard(chunk_hash)
            
            # 立即检查是否还有可用peer
            available_peers = [
                p for p in self.chunk_sources.get(chunk_hash, [])
                if p != peer_addr and (
                    p not in self.suspected_peers or 
                    current_time - self.suspected_peers.get(p, 0) > self.peer_retry_delay
                )
            ]
            
            if available_peers:
                new_peer = available_peers[0]
                logging.info(f"🔄 Switching to peer {new_peer} for chunk {chunk_hash.hex()[:16]}...")
                self._start_download_from_peer(sock, chunk_hash, new_peer)
            else:
                logging.warning(f"⚠️ No available peers for chunk {chunk_hash.hex()[:16]}... after peer suspected")
        else:
            logging.debug(f"仍有 {len(active_peers)} 个活跃peer，不立即恢复")

    def _check_active_download_timeout(self) -> bool:
        """检查活跃下载是否超时"""
        if self.active_download is None:
            return False
        
        # 简单超时检查：如果chunk尝试次数过多，认为超时
        attempts = self.chunk_attempts.get(self.active_download, 0)
        return attempts >= self.max_attempts
    
    def _handle_download_failure(self, sock: simsocket.SimSocket, chunk_hash: bytes) -> None:
        """处理下载失败"""
        peer_addr = self.chunk_to_peer_map.get(chunk_hash)
        
        # 标记peer可疑
        if peer_addr:
            self.suspected_peers[peer_addr] = time.time()
        
        # 清理失败状态
        self._cleanup_failed_download(chunk_hash, peer_addr)
        
        # 如果还有尝试机会，重新调度
        attempts = self.chunk_attempts.get(chunk_hash, 0)
        if attempts < self.max_attempts:
            logging.info(f"Will retry chunk {chunk_hash.hex()[:16]} (attempt {attempts+1}/{self.max_attempts})")
            self.schedule_downloads(sock)
        else:
            logging.error(f"Permanently failed for chunk {chunk_hash.hex()[:16]}")

def process_download(sock: simsocket.SimSocket, chunk_file: str, output_file: str) -> None:
    """
    Initiates and manages the download of one or more chunks.

    This function is called when a 'DOWNLOAD' command is received. It is
    responsible for reading the chunk hashes from the ``chunk_file``,
    orchestrating the network requests (e.g., sending WHOHAS, GET) to
    retrieve all necessary chunks, and saving the completed data to
    the ``output_file``.

    :param sock: The :class:`simsocket.SimSocket` for network communication.
    :param chunk_file: Path to the file containing hashes of chunks to download.
    :param output_file: Path to the file to save the downloaded chunk data.
    """
    logging.info(f"🎯 [Peer {sock._node_id}] ====== START DOWNLOAD ======")
    logging.info(f"Target file: {chunk_file}, Output: {output_file}")
    
    try:
        # 确保 download_manager 存在
        if not hasattr(sock, 'download_manager'):
            logging.debug("Creating new download_manager")
            sock.download_manager = DownloadManager()
        
        # Read chunk hashes from file
        chunk_hashes = _read_chunk_hash_file(chunk_file)
        
        if not chunk_hashes:
            logging.error(f"No valid chunk hashes found in {chunk_file}")
            return
        
        logging.info(f"Read {len(chunk_hashes)} chunk hashes from file")
        
        # 显示每个chunk的hash（前几位）
        for i, chunk_hash in enumerate(chunk_hashes):
            if isinstance(chunk_hash, bytes):
                logging.info(f"  Chunk {i}: {chunk_hash.hex()[:16]}...")
            else:
                logging.warning(f"  Chunk {i}: Invalid type {type(chunk_hash)}")
        
        # Filter out chunks already available locally
        missing_hashes = []
        for chunk_hash in chunk_hashes:
            if chunk_hash not in sock.peer_state.local_chunks:
                missing_hashes.append(chunk_hash)
        
        logging.info(f"Missing chunks: {len(missing_hashes)} (already have {len(chunk_hashes) - len(missing_hashes)})")
        
        if not missing_hashes:
            logging.info("All chunks already available locally, nothing to download")
            # 即使没有要下载的，也应该保存结果文件
            try:
                result = {}
                for chunk_hash in chunk_hashes:
                    if chunk_hash in sock.peer_state.local_chunks:
                        result[chunk_hash.hex()] = sock.peer_state.local_chunks[chunk_hash]
                
                with open(output_file, 'wb') as f:
                    pickle.dump(result, f)
                logging.info(f"Saved existing chunks to {output_file}")
            except Exception as e:
                logging.error(f"Error saving existing chunks: {e}")
            return
        
        # Start download using download manager
        sock.download_manager.start_download(missing_hashes, output_file)
        
        # Send WHOHAS to all known peers
        known_peers = sock.peer_state.known_peers
        logging.info(f"Sending WHOHAS to {len(known_peers)} known peers:")
        for peer_addr in known_peers:
            logging.info(f"  - {peer_addr}")
        
        # 发送WHOHAS包  
        send_whohas(sock, missing_hashes, known_peers)
        logging.info("WHOHAS packets sent successfully")
        
        logging.info("Download process initiated")
        
    except Exception as e:
        logging.error(f"Error in process_download: {e}")
        import traceback
        traceback.print_exc()


def _read_chunk_hash_file(chunk_file: str):
    """Read .chunkhash file - support multiple formats"""
    logging.debug(f"Reading chunk file: {chunk_file}")
    try:
        with open(chunk_file, 'r') as f:
            content = f.read()
            logging.debug(f"File content: {repr(content)}")
            
        lines = content.strip().split('\n')
        logging.debug(f"Found {len(lines)} lines")
        
        chunk_hashes = []
        for i, line in enumerate(lines):
            line = line.strip()
            logging.debug(f"Line {i}: '{line}'")
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Debug: print each part of the line
            parts = line.split()
            logging.debug(f"  Parts: {parts}")
            
            for j, part in enumerate(parts):
                logging.debug(f"    Part {j}: '{part}' (len={len(part)})")
                if len(part) == 40:
                    logging.debug(f"    -> Found 40-char part, testing if hex: {part}")
                    try:
                        # Test if it can be converted to bytes
                        test_bytes = bytes.fromhex(part)
                        logging.debug(f"    -> Successfully converted to bytes: {test_bytes.hex()}")
                        chunk_hash = test_bytes
                        chunk_hashes.append(chunk_hash)
                        logging.debug(f"    -> Added to chunk_hashes")
                        break
                    except ValueError as e:
                        logging.debug(f"    -> Not valid hex: {e}")
                        continue
        
        logging.debug(f"Parsed {len(chunk_hashes)} valid chunk hashes")
        return chunk_hashes
        
    except Exception as e:
        logging.error(f"Error reading {chunk_file}: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return []


def process_inbound_udp(sock: simsocket.SimSocket) -> None:
    """
    Processes a single inbound packet received from the socket.

    This function should receive data, unpack the standard header,
    and then use the packet type to route the packet to the appropriate
    handling logic (e.g., for WHOHAS, IHAVE, GET, DATA, ACK).

    :param sock: The :class:`simsocket.SimSocket` with a pending packet.
    :type sock: simsocket.SimSocket
    """
    # Receive packet
    pkt: bytes
    from_addr: AddressType
    pkt, from_addr = sock.recvfrom(BUF_SIZE)

    logging.info(f"=== DEBUG: Received packet from {from_addr}, length: {len(pkt)} ===")

    try:
        # 修改解析调用，现在返回7个值
        pkg_type, hlen, plen, seq, ack, flags, data = parse_packet(pkt)
        logging.info(f"DEBUG: Packet type: {pkg_type}, seq: {seq}, ack: {ack}, flags: {flags}")
        
        # Route packet based on type
        if pkg_type == PKG_WHOHAS:
            _handle_whohas(sock, from_addr, data)
        elif pkg_type == PKG_IHAVE:
            _handle_ihave(sock, from_addr, data)
        elif pkg_type == PKG_GET:
            _handle_get(sock, from_addr, data)
        elif pkg_type == PKG_DATA:
            # 对于DATA包，flags包含结束标记
            is_last = (flags & FLAG_LAST_PACKET) != 0
            _handle_data(sock, from_addr, seq, data, is_last)  # 传递is_last
        elif pkg_type == PKG_ACK:
            _handle_ack(sock, from_addr, ack)
        elif pkg_type == PKG_DENIED:
            _handle_denied(sock, from_addr)
        else:
            logging.info(f"DEBUG: Unknown packet type: {pkg_type}")

    except Exception as e:
        logging.info(f"DEBUG: Error processing packet: {e}")

def _handle_whohas(sock: simsocket.SimSocket, from_addr: AddressType, data: bytes) -> None:
    """Handle WHOHAS packet: check local chunks, reply IHAVE or DENIED"""
    try:
        # Parse requested chunk hash list
        requested_hashes = pickle.loads(data)
        peer_id = sock._node_id if hasattr(sock, '_node_id') else 'unknown'
        my_addr = sock._address if hasattr(sock, '_address') else 'unknown'
        logging.debug(f"Peer {peer_id} at {my_addr} Received WHOHAS from {from_addr} for {len(requested_hashes)} chunks")
        
        # Check locally available chunks
        available_hashes = []
        for chunk_hash in requested_hashes:
            if chunk_hash in sock.peer_state.local_chunks:
                available_hashes.append(chunk_hash)
        
        logging.debug(f"Local available chunks: {len(available_hashes)}")
        
        # If no available chunks, do not reply according to protocol
        if not available_hashes:
            logging.debug(f"No requested chunks available for {from_addr}, not replying")
            return
        
        # Check connection limit
        if not sock.peer_state.can_accept_upload():
            send_denied(sock, from_addr)
            logging.debug(f"Sent DENIED to {from_addr} (max connections reached)")
            return
        
        # Has available chunks and connection not full, send IHAVE
        send_ihave(sock, from_addr, available_hashes)
        logging.debug(f"Sent IHAVE to {from_addr} with {len(available_hashes)} chunks")
        
    except Exception as e:
        logging.error(f"Error handling WHOHAS from {from_addr}: {e}")


def _handle_ihave(sock: simsocket.SimSocket, from_addr: AddressType, data: bytes) -> None:
    """Handle IHAVE packet: update download manager with available chunks"""
    try:
        logging.info(f"=== DEBUG: Received IHAVE from {from_addr} ===")
        
        # 确保 download_manager 存在
        if not hasattr(sock, 'download_manager'):
            logging.info("DEBUG: No download_manager found!")
            return
            
        available_hashes = pickle.loads(data)
        logging.info(f"DEBUG: Available chunks count: {len(available_hashes)}")
        
        # Update download manager
        sock.download_manager.on_ihave_received(from_addr, available_hashes)
        
        # Immediately try to schedule downloads
        logging.info("DEBUG: Calling schedule_downloads")
        sock.download_manager.schedule_downloads(sock)
        logging.info("DEBUG: schedule_downloads completed")
        
    except Exception as e:
        logging.info(f"DEBUG: Error in _handle_ihave: {e}")


def _handle_get(sock: simsocket.SimSocket, from_addr: AddressType, data: bytes) -> None:
    """Handle GET packet: start sending requested chunk data with RDT"""
    try:
        chunk_hash = data
        logging.info(f"Handling GET from {from_addr} for chunk {chunk_hash.hex()[:16]}...")
        
        # Check connection limit
        if not sock.peer_state.can_accept_upload():
            logging.info("Connection limit reached, sending DENIED")
            send_denied(sock, from_addr)
            return
        
        # Check if local has this chunk
        if chunk_hash not in sock.peer_state.local_chunks:
            logging.info(f"Requested chunk not found locally: {chunk_hash.hex()[:16]}...")
            return
        
        # Get chunk data
        chunk_data = sock.peer_state.local_chunks[chunk_hash]
        logging.info(f"Starting upload session for chunk {chunk_hash.hex()[:16]}..., size: {len(chunk_data)} bytes")
        
        # Start upload session with RDT
        if sock.peer_state.start_upload_session(from_addr, chunk_hash, chunk_data):
            session = sock.peer_state.get_upload_session(from_addr)
            logging.info(f"Created upload session, total packets: {len(session.packets)}")
            
            # Send first packet - 使用新的send_data函数
            packet_info = session.get_next_packet_to_send()
            if packet_info:
                seq, packet_data, is_last = packet_info
                send_data(sock, from_addr, seq, packet_data, is_last)
                session.mark_packet_sent(seq, packet_data, is_last)
                logging.info(f"Sent first DATA packet to {from_addr}, seq={seq}, is_last={is_last}")
            else:
                logging.error(f"No packets to send for chunk {chunk_hash.hex()[:16]}...")
                sock.peer_state.remove_upload_session(from_addr)
        else:
            send_denied(sock, from_addr)
            logging.info(f"Sent DENIED to {from_addr} (upload session failed)")

    except Exception as e:
        logging.error(f"Error handling GET from {from_addr}: {e}")
        import traceback
        logging.error(traceback.format_exc())

def _find_download_session_for_data(sock: simsocket.SimSocket, from_addr: AddressType) -> Optional[TransferSession]:
    """Find download session for DATA packet by peer address"""
    # Iterate through all download sessions to find the one with matching peer address
    for chunk_hash, session in sock.peer_state.download_sessions.items():
        if session.peer_addr == from_addr:
            return session
    return None

def _handle_data(sock: simsocket.SimSocket, from_addr: AddressType, seq: int, data: bytes, is_last: bool) -> None:
    """Handle DATA packet with RDT - 修复竞态条件和会话查找问题"""
    try:
        # 1. 立即发送ACK
        send_ack(sock, from_addr, seq)
        
        logging.debug(f"Received DATA from {from_addr}, seq={seq}, is_last={is_last}, size={len(data)}")
        
        # 2. 首先尝试通过peer_addr查找会话
        session = sock.peer_state.get_download_session(from_addr)
        
        # 3. 如果没找到会话，检查是否是当前活跃下载
        if not session:
            if hasattr(sock, 'download_manager') and sock.download_manager.is_active:
                dm = sock.download_manager
                
                # 检查是否有活跃下载
                if dm.active_download:
                    current_chunk = dm.active_download
                    
                    # 关键修复：检查这个peer是否应该发送这个chunk
                    expected_peer = dm.chunk_to_peer_map.get(current_chunk)
                    
                    if expected_peer == from_addr:
                        # 这是正确的peer，但会话还没创建或丢失了
                        logging.warning(f"⚠️ DATA from correct peer {from_addr} but no session found. "
                                      f"Active chunk: {current_chunk.hex()[:16]}...")
                        
                        # 尝试重新创建会话
                        try:
                            # 先检查是否已经有其他会话（清理残留）
                            existing_sessions = sock.peer_state.get_all_sessions()
                            for s in existing_sessions:
                                if s.peer_addr == from_addr:
                                    logging.info(f"Found existing session for {from_addr}, removing")
                                    sock.peer_state.remove_download_session(from_addr)
                                    break
                            
                            # 创建新会话
                            session = sock.peer_state.start_download_session(from_addr, current_chunk)
                            logging.info(f"✅ Recreated download session for {from_addr}, "
                                        f"chunk {current_chunk.hex()[:16]}...")
                            
                        except Exception as e:
                            logging.error(f"Failed to recreate session: {e}")
                            return
                    else:
                        # 错误的peer，或者peer映射有问题
                        logging.warning(f"❌ DATA from unexpected peer {from_addr}. "
                                      f"Expected {expected_peer} for chunk {current_chunk.hex()[:16]}...")
                        return
                else:
                    # 没有活跃下载，但收到了DATA
                    logging.warning(f"📭 Received DATA but no active download. Peer: {from_addr}")
                    return
            else:
                # 没有DownloadManager或不在活跃状态
                logging.debug(f"No active download manager for DATA from {from_addr}")
                return
        
        # 4. 验证会话的chunk是否匹配当前活跃下载
        if hasattr(sock, 'download_manager') and sock.download_manager.is_active:
            dm = sock.download_manager
            if dm.active_download and session.chunk_hash != dm.active_download:
                logging.warning(f"⚠️ Session chunk mismatch! Session has {session.chunk_hash.hex()[:16]}... "
                              f"but active is {dm.active_download.hex()[:16]}...")
                
                # 如果活跃下载已经改变，需要更新会话
                if session.chunk_hash in dm.downloaded_chunks:
                    # 这个chunk已经下载完成，会话应该已经被清理
                    logging.info(f"Chunk {session.chunk_hash.hex()[:16]} already downloaded, cleaning old session")
                    sock.peer_state.remove_download_session(from_addr)
                    return
        
        # 5. 通知DownloadManager收到数据包
        if hasattr(sock, 'download_manager'):
            sock.download_manager.on_data_received(from_addr, session.chunk_hash, seq, data, is_last)
        
        # 6. 处理接收的数据（使用新的乱序处理逻辑）
        session.on_data_received(seq, data, is_last)
        
        received_count = len(session.received_packets)
        logging.debug(f"Download progress: {received_count} packets received, "
                     f"next_seq={session.next_seq}, buffered={len(session.out_of_order_buffer)}")
        
        # 7. 关键修改：不立即检查完成，只在is_last时记录
        if is_last:
            logging.info(f"Received LAST packet: seq={seq}, will check completion in timeout loop")
            
            # 标记收到了LAST标志，但不立即检查
            # TransferSession的is_complete()方法会自己管理完成检查
            session.last_packet_received = True
        
        # 8. 定期检查是否完成（但不是每次收到包都检查）
        # 让check_all_timeouts函数定期检查
        
    except Exception as e:
        logging.error(f"Error handling DATA from {from_addr}: {e}")
        import traceback
        logging.error(traceback.format_exc())

def _handle_ack(sock: simsocket.SimSocket, from_addr: AddressType, ack: int) -> None:
    """Handle ACK packet with TCP congestion control"""
    try:
        # Find upload session for this peer
        session = sock.peer_state.get_upload_session(from_addr)
        if not session:
            return
        
        # Process the ACK with congestion control
        is_new_ack = session.on_ack_received(ack)
        
        if is_new_ack or session.state == "fast_recovery":
            # 发送可用的新包（考虑拥塞窗口）
            packets_to_send = session.get_packets_to_send()
            for seq, packet_data, is_last in packets_to_send:
                send_data(sock, from_addr, seq, packet_data, is_last)
                session.mark_packet_sent(seq, packet_data, is_last, is_retransmit=False)
                logging.debug(f"Sent DATA packet to {from_addr}, seq={seq}, is_last={is_last}, cwnd={session.cwnd:.1f}")
        
        # 检查快速重传
        if session.should_retransmit():
            packets_to_retransmit = session.get_packets_for_retransmit()
            for seq in packets_to_retransmit:
                if seq in session.sent_packets:
                    packet_data, _, _ = session.sent_packets[seq]
                    # 关键修改：判断是否是最后一个包
                    is_last = (seq == len(session.packets))
                    send_data(sock, from_addr, seq, packet_data, is_last)
                    session.mark_packet_sent(seq, packet_data, is_last, is_retransmit=True)
                    logging.debug(f"Fast retransmit to {from_addr}, seq={seq}, is_last={is_last}")
        
        # Check if upload is complete
        if session.is_complete():
            sock.peer_state.remove_upload_session(from_addr)
            logging.info(f"Upload completed for chunk {session.chunk_hash.hex()[:16]}... to {from_addr}")
                
    except Exception as e:
        logging.error(f"Error handling ACK from {from_addr}: {e}")

def _handle_denied(sock: simsocket.SimSocket, from_addr: AddressType) -> None:
    """Handle DENIED packet: record denied connection"""
    if sock.peer_state.context.verbose >= 2:
        logging.info(f"Received DENIED from {from_addr}")

def check_all_timeouts(sock: simsocket.SimSocket) -> None:
    """Check all active transmission timeouts with congestion control"""
    current_time = time.time()
    
    # 检查上传会话（保持不变）
    for peer_addr, session in list(sock.peer_state.upload_sessions.items()):
        try:
            timed_out_packets = session.get_timed_out_packets()
            if timed_out_packets:
                # 超时发生，处理拥塞控制
                session._handle_timeout()
                logging.warning(f"Timeout detected for {peer_addr}, resetting cwnd to 1")
                
                # 重传所有超时的包，正确设置is_last
                for seq in timed_out_packets:
                    if seq in session.sent_packets:
                        packet_info = session.sent_packets[seq]
                        # 安全解包
                        if len(packet_info) == 4:
                            packet_data, sent_time, is_retransmit, is_last = packet_info
                        elif len(packet_info) == 3:
                            packet_data, sent_time, is_retransmit = packet_info
                            is_last = (seq == len(session.packets))
                        else:
                            continue
                        
                        # 发送时传递正确的is_last
                        send_data(sock, peer_addr, seq, packet_data, is_last)
                        # 更新发送记录
                        session.mark_packet_sent(seq, packet_data, is_last, is_retransmit=True)
                        logging.debug(f"Timeout retransmit to {peer_addr}, seq={seq}, is_last={is_last}")

            # 发送可用的新包
            packets_to_send = session.get_packets_to_send()
            for seq, packet_data, is_last in packets_to_send:
                send_data(sock, peer_addr, seq, packet_data, is_last)
                session.mark_packet_sent(seq, packet_data, is_last, is_retransmit=False)
            
            # 检查快速重传
            if session.should_retransmit():
                packets_to_retransmit = session.get_packets_for_retransmit()
                for seq, packet_data, is_last in packets_to_retransmit:
                    if seq in session.sent_packets:
                        send_data(sock, peer_addr, seq, packet_data, is_last)
                        session.mark_packet_sent(seq, packet_data, is_last, is_retransmit=True)
                        logging.debug(f"Fast retransmit to {peer_addr}, seq={seq}, is_last={is_last}")
            
            # 会话超时清理
            if current_time - session.last_activity > 60.0:
                sock.peer_state.remove_upload_session(peer_addr)
                logging.debug(f"Upload session timeout for {peer_addr}")
                
        except Exception as e:
            logging.error(f"Error checking timeout for upload session {peer_addr}: {e}")

    # 检查下载会话 - 修改后的逻辑
    for peer_addr, session in list(sock.peer_state.download_sessions.items()):
        try:
            inactive_time = current_time - session.last_activity
            chunk_hash = session.chunk_hash  # 在try块开始处定义，确保整个作用域可用
            
            # 关键修改：检查是否有活跃的DownloadManager
            if hasattr(sock, 'download_manager') and sock.download_manager.is_active:
                dm = sock.download_manager
                
                # 关键新增：定期检查下载会话是否完成
                if session.is_complete():
                    logging.info(f"🎉 Download session completed in timeout check: "
                                f"chunk={chunk_hash.hex()[:16]}, peer={peer_addr}")
                    
                    try:
                        # 组装完整的chunk
                        chunk_data = session.assemble_chunk()
                        logging.info(f"Assembled chunk size: {len(chunk_data)} bytes")
                        
                        # 验证chunk hash
                        computed_hash = hashlib.sha1(chunk_data).digest()
                        if computed_hash == chunk_hash:
                            logging.info(f"Chunk hash verified successfully!")
                            
                            # 通知DownloadManager
                            if hasattr(sock, 'download_manager'):
                                sock.download_manager.on_chunk_received(sock, chunk_hash, chunk_data)
                            
                            # 清理会话
                            sock.peer_state.remove_download_session(peer_addr)
                            logging.info(f"Download session cleaned up")
                            
                        else:
                            logging.error(f"Chunk hash mismatch!")
                            logging.error(f"Expected: {chunk_hash.hex()}, Got: {computed_hash.hex()}")
                            
                    except Exception as e:
                        logging.error(f"Error assembling chunk in timeout check: {e}")
                        import traceback
                        logging.error(traceback.format_exc())
                
                # 检查这个session对应的chunk是否是当前活跃下载
                if dm.active_download == chunk_hash:
                    # 这是当前正在下载的chunk，使用较短的超时时间
                    if inactive_time > 8.0:  # 8秒无活动认为是可能有问题
                        logging.warning(f"🚨 Active download appears stuck: peer={peer_addr}, "
                                      f"chunk={chunk_hash.hex()[:16]}, "
                                      f"inactive={inactive_time:.1f}s")
                        
                        if inactive_time > 12.0:  # 12秒认为是peer可能崩溃
                            logging.error(f"🔴 Peer may have crashed: {peer_addr}")
                            
                            # 先清理session
                            sock.peer_state.remove_download_session(peer_addr)
                            
                            # 通知DownloadManager处理peer崩溃
                            dm.on_peer_crash(sock, chunk_hash, peer_addr)
                            
                        else:
                            # 只是超时，标记为可疑
                            if peer_addr not in dm.suspected_peers:
                                dm.suspected_peers[peer_addr] = current_time
                                logging.info(f"⚠️ Marked peer {peer_addr} as suspected")
                            
                            # 检查是否需要重新调度
                            if inactive_time > 10.0 and dm.active_download == chunk_hash:
                                logging.info(f"Triggering retry for stuck download")
                                dm._handle_download_failure(sock, chunk_hash)
                    
                    elif inactive_time > 60.0:  # 绝对超时，彻底清理
                        logging.warning(f"Download session absolute timeout for {peer_addr}")
                        
                        # 清理session
                        sock.peer_state.remove_download_session(peer_addr)
                        
                        # 通知DownloadManager
                        if dm.active_download == chunk_hash:
                            dm._cleanup_failed_download(chunk_hash, peer_addr)
                
                else:
                    # 这个session不属于当前活跃下载（可能是旧会话残留）
                    if inactive_time > 30.0:
                        logging.debug(f"Removing stale download session for {peer_addr}")
                        sock.peer_state.remove_download_session(peer_addr)
            
            else:
                # 没有活跃的DownloadManager，使用默认超时
                if inactive_time > 60.0:
                    logging.debug(f"Download session timeout for {peer_addr} (no active manager)")
                    sock.peer_state.remove_download_session(peer_addr)
                    
        except Exception as e:
            logging.error(f"Error checking timeout for download session {peer_addr}: {e}")
            
def process_user_input(sock: simsocket.SimSocket) -> None:
    """
    Handles a single line of user input from ``sys.stdin``.

    Parses the input and, if the command is "DOWNLOAD", calls
    :func:`process_download` with the provided file paths.

    :param sock: The :class:`simsocket.SimSocket` to be passed to
                 :func:`process_download`.
    :type sock: simsocket.SimSocket
    """
    try:
        logging.info("=== DEBUG: process_user_input ENTERED ===")
        
        # 使用select检查stdin是否有输入，避免阻塞
        import select
        rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
        logging.info(f"DEBUG: select result - rlist: {rlist}")
        
        if not rlist:
            logging.info("DEBUG: No stdin input available")
            return  # 没有输入可用
        
        line = sys.stdin.readline()
        logging.info(f"DEBUG: Read line: '{line}'")
        
        if not line:
            logging.info("DEBUG: EOF reached")
            return  # 读取到EOF
            
        line = line.strip()
        if not line:
            logging.info("DEBUG: Empty line")
            return  # 空行
        
        logging.info(f"DEBUG: Processing command: '{line}'")
        
        # 解析命令
        parts = line.split()
        logging.info(f"DEBUG: Command parts: {parts}")
        
        if len(parts) < 3:
            logging.warning(f"DEBUG: Invalid command format: {line}")
            return
            
        cmd = parts[0].upper()
        chunk_file = parts[1]
        output_file = parts[2]
        
        logging.info(f"DEBUG: Parsed - CMD: {cmd}, chunk_file: {chunk_file}, output_file: {output_file}")
        
        if cmd == "DOWNLOAD":
            logging.info(f"DEBUG: Calling process_download...")
            process_download(sock, chunk_file, output_file)
        else:
            logging.warning(f"DEBUG: Unknown command: {cmd}")
            
    except Exception as e:
        logging.error(f"DEBUG: Error in process_user_input: {e}")
        import traceback
        traceback.print_exc()


def peer_run(context: PeerContext) -> None:
    """
    Runs the main event loop for the peer.

    Initializes the :class:`simsocket.SimSocket` and enters a loop
    that uses :func:`select.select` to monitor both the socket for
    inbound packets (handled by :func:`process_inbound_udp`) and
    ``sys.stdin`` for user commands (handled by
    :func:`process_user_input`).

    :param context: The peer's configuration and state object.
    """
    addr: AddressType = (context.ip, context.port)
    peer_state = PeerState(context)
    sock = simsocket.SimSocket(context.identity, addr, verbose=context.verbose)
    sock.peer_state = peer_state
    
    # 初始化 download_manager
    sock.download_manager = DownloadManager()
    
    logging.info(f"Peer started at {addr}, identity={context.identity}")
    logging.info(f"Known peers: {len(peer_state.known_peers)}")
    logging.info(f"Local chunks: {len(peer_state.local_chunks)}")
    
    # 关键：确保peer已经正确初始化
    logging.info("Peer initialization complete. Ready for commands.")
    
    try:
        while True:
            logging.debug("=== Main loop iteration ===")
            
            # 使用select监控socket和stdin
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            
            logging.debug(f"DEBUG: select returned - read_ready: {read_ready}")
            
            if sock in read_ready:
                logging.debug("DEBUG: Socket has data, calling process_inbound_udp")
                process_inbound_udp(sock)
            
            if sys.stdin in read_ready:
                logging.debug("DEBUG: stdin has data, calling process_user_input")
                process_user_input(sock)
                
            # 定期检查超时
            check_all_timeouts(sock)
                
    except KeyboardInterrupt:
        logging.info("Peer shutting down...")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()


def main() -> None:
    """
    Main entry point for the peer script.

    Parses command-line arguments, initializes the global PeerContext,
    and starts the peer's main run loop.
    """

    """
    -i: ID, it is the index in nodes.map

    -p: Peer list file, it will be in the form "*.map" like nodes.map.

    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in peer_context.
        The loaded dictionary has the form: {chunkhash: chunkdata}

    -m: The max number of peer that you can send chunk to concurrently.
        If more peers ask you for chunks, you should reply "DENIED"

    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.

    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT.
        If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    
    parser = argparse.ArgumentParser(
        description="CS305 Project Peer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--identity", dest="identity", type=int, help="Which peer # am I?")
    parser.add_argument("-p", "--peer-file", dest="peer_file", type=str, default="nodes.map")
    parser.add_argument("-c", "--chunk-file", dest="chunk_file", type=str, help="Chunk hash file")
    parser.add_argument("-m", "--max-conn", dest="max_conn", type=int, help="Max # of concurrent sending")
    parser.add_argument("-v", "--verbose", dest="verbose", type=int, default=0)
    parser.add_argument("-t", "--timeout", dest="timeout", type=int, default=0)
    
    args = parser.parse_args()

    log_name = f'peer_{args.identity}.log' if args.identity is not None else 'peer_unknown.log'
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_name,  # <--- 这里改成了动态文件名
        filemode='w'
    )

    # 3. 启动 Peer
    context = PeerContext(args)
    peer_run(context)

if __name__ == "__main__":
    main()