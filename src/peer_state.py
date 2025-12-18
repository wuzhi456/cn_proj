import time
import logging
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional
from utils.simsocket import AddressType
from utils.peer_context import PeerContext
from src.packet_utils import HEADER_LEN

class TransferSession:
    """管理单个chunk的传输会话，实现TCP风格拥塞控制"""
    def __init__(self, peer_addr, chunk_hash: bytes, chunk_data: bytes = None, is_upload: bool = True):
        self.peer_addr = peer_addr
        self.chunk_hash = chunk_hash
        self.is_upload = is_upload
        self.start_time = time.time()
        self.last_activity = time.time()
        
        # RDT状态
        self.next_seq = 1
        self.acked_packets: Set[int] = set()
        self.sent_packets: Dict[int, tuple] = {}  # {seq: (data, sent_time, is_retransmit)}
        self.received_packets: Dict[int, bytes] = {}
        
        # TCP拥塞控制状态
        self.cwnd = 1.0  # 拥塞窗口 (packets)
        self.ssthresh = 64.0  # 慢启动阈值
        self.in_flight = 0  # 已发送未确认的包数
        self.dup_ack_count = 0
        self.last_dup_ack = 0
        self.state = "slow_start"  # slow_start, congestion_avoidance, fast_recovery
        
        # RTT估计 (TCP标准参数)
        self.estimated_rtt = 1.0  # 初始估计1秒
        self.dev_rtt = 0.0
        self.alpha = 0.125  # RFC 6298推荐值
        self.beta = 0.25
        self.timeout_interval = 1.0  # 初始超时1秒
        
        # 分片相关
        self.header_length = HEADER_LEN
        self.max_packet_size = 1400
        self.packet_size = self.max_packet_size - self.header_length
        self.packets: List[bytes] = []
        
        # 传输状态
        self.last_packet_sent = False
        self.last_packet_received = False
        self.expected_last_seq = None
        
        # 对于下载会话的特殊状态
        self.last_data_time = time.time()
        self.consecutive_empty_cycles = 0
        
        # 乱序处理相关（新添加）
        self.out_of_order_buffer = {}  # 乱序包缓存 {seq: data}
        self.max_received_seq = 0      # 收到过的最大序列号
        self.has_received_last_flag = False  # 是否收到过LAST标志
        
        if is_upload and chunk_data:
            self.packets = self._split_into_packets(chunk_data)

    def _split_into_packets(self, chunk_data: bytes) -> List[bytes]:
        """将chunk数据分成多个数据包"""
        packets = []
        data_len = len(chunk_data)
        
        for i in range(0, data_len, self.packet_size):
            end_idx = min(i + self.packet_size, data_len)
            packet_data = chunk_data[i:end_idx]
            packets.append(packet_data)
            
        logging.debug(f"Split {data_len} bytes into {len(packets)} packets of max {self.packet_size} bytes")
        return packets
    
    def get_available_window(self) -> int:
        """获取当前可发送的包数量"""
        available = int(self.cwnd) - self.in_flight
        max_available = len(self.packets) - self.next_seq + 1
        return max(0, min(available, max_available))
    
    def get_packets_to_send(self) -> List[Tuple[int, bytes, bool]]:
        """获取当前可以发送的包列表"""
        available = self.get_available_window()
        packets_to_send = []
        
        for i in range(available):
            seq = self.next_seq + i
            if seq > len(self.packets):
                break
                
            packet_data = self.packets[seq - 1]
            is_last = (seq == len(self.packets))
            packets_to_send.append((seq, packet_data, is_last))
            
        return packets_to_send
    
    def mark_packet_sent(self, seq: int, packet_data: bytes, is_last: bool = False, is_retransmit: bool = False) -> None:
        """标记数据包已发送"""
        # 保存所有必要信息
        self.sent_packets[seq] = (packet_data, time.time(), is_retransmit, is_last)  # 添加is_last
        self.last_activity = time.time()
    
        if not is_retransmit:
            self.in_flight += 1
            # 只有新发送的包才更新next_seq
            if seq == self.next_seq:
                self.next_seq += 1

        if is_last:
            self.last_packet_sent = True
            self.expected_last_seq = seq
            logging.info(f"Marked packet {seq} as LAST packet")
    
    def _update_rtt(self, sample_rtt: float) -> None:
        """更新RTT估计 (TCP标准算法)"""
        if sample_rtt is None:
            return
            
        if self.estimated_rtt == 1.0:  # 初始值
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.estimated_rtt = (1 - self.alpha) * self.estimated_rtt + self.alpha * sample_rtt
            self.dev_rtt = (1 - self.beta) * self.dev_rtt + self.beta * abs(sample_rtt - self.estimated_rtt)
        
        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt
        logging.debug(f"RTT updated: sample={sample_rtt:.3f}, est={self.estimated_rtt:.3f}, timeout={self.timeout_interval:.3f}")
    
    def on_ack_received(self, ack_seq: int) -> bool:
        """处理ACK包，实现TCP拥塞控制"""
        current_time = time.time()
        self.last_activity = current_time
    
        # 计算RTT样本
        if ack_seq in self.sent_packets:
            packet_info = self.sent_packets[ack_seq]
            # 解包，支持新旧两种格式
            if len(packet_info) == 4:
                packet_data, sent_time, is_retransmit, is_last = packet_info
            else:
                # 旧格式：只有3个元素
                packet_data, sent_time, is_retransmit = packet_info
                is_last = False
            
            if not is_retransmit:  # 重传的包不用于RTT估计
                sample_rtt = current_time - sent_time
                self._update_rtt(sample_rtt)
    
        if ack_seq in self.acked_packets:
            # 重复ACK
            if ack_seq == self.last_dup_ack:
                self.dup_ack_count += 1
            else:
                self.dup_ack_count = 1
                self.last_dup_ack = ack_seq
        
            # 快速重传触发条件
            if self.dup_ack_count == 3 and self.state != "fast_recovery":
                self._enter_fast_recovery()
                return False
            elif self.state == "fast_recovery":
                # 在快速恢复阶段，每个重复ACK增加cwnd
                self.cwnd += 1
                return False
            else:
                return False
        else:
            # 新的ACK
            self.acked_packets.add(ack_seq)
        
            # 修复：只在包确实在飞行中时才减少计数
            if ack_seq in self.sent_packets:
                # 确保in_flight不会变成负数
                if self.in_flight > 0:
                    self.in_flight -= 1
                else:
                    logging.warning(f"in_flight already 0 or negative for ACK {ack_seq}")
                    self.in_flight = 0  # 重置为0
        
            if self.state == "fast_recovery":
                # 快速恢复阶段收到新ACK，退出快速恢复
                self.cwnd = self.ssthresh
                self.state = "congestion_avoidance"
                self.dup_ack_count = 0
            elif self.state == "slow_start":
                # 慢启动：每个ACK cwnd+1
                self.cwnd += 1
                if self.cwnd >= self.ssthresh:
                    self.state = "congestion_avoidance"
                    logging.info(f"Transition to congestion avoidance: cwnd={self.cwnd:.1f}")
            elif self.state == "congestion_avoidance":
                # 拥塞避免：每个RTT cwnd+1 (每个ACK cwnd+1/cwnd)
                self.cwnd += 1.0 / self.cwnd
        
            self.dup_ack_count = 0
            logging.debug(f"New ACK {ack_seq}: cwnd={self.cwnd:.1f}, in_flight={self.in_flight}, state={self.state}")
            return True
    
    def _enter_fast_recovery(self) -> None:
        """进入快速恢复状态"""
        logging.info(f"Entering fast recovery: cwnd={self.cwnd:.1f} -> {self.ssthresh:.1f}")
        self.ssthresh = max(self.cwnd / 2, 2)
        self.cwnd = self.ssthresh + 3  # 为3个重复ACK做补偿
        self.state = "fast_recovery"
        self.dup_ack_count = 0
    
    def _handle_timeout(self) -> None:
        """处理超时事件"""
        logging.warning(f"Timeout occurred: cwnd={self.cwnd:.1f} -> 1")
        self.ssthresh = max(self.cwnd / 2, 2)
        self.cwnd = 1
        self.state = "slow_start"
        self.dup_ack_count = 0
        self.in_flight = 0  # 重置飞行中的包计数
    
        # 重置所有已发送但未确认的包
        for seq in list(self.sent_packets.keys()):
            if seq not in self.acked_packets:
                packet_info = self.sent_packets[seq]
                # 安全解包
                if len(packet_info) == 4:
                    packet_data, sent_time, is_retransmit, is_last = packet_info
                elif len(packet_info) == 3:
                    packet_data, sent_time, is_retransmit = packet_info
                else:
                    continue
                self.sent_packets[seq] = (packet_data, time.time(), True, is_last if 'is_last' in locals() else False)
    
    def get_timed_out_packets(self) -> List[int]:
        """获取超时的数据包序号列表"""
        current_time = time.time()
        timed_out = []
    
        for seq, packet_info in self.sent_packets.items():
            # 安全解包
            if len(packet_info) == 4:
                data, sent_time, is_retransmit, is_last = packet_info
            elif len(packet_info) == 3:
                data, sent_time, is_retransmit = packet_info
            else:
                logging.error(f"Invalid packet_info format for seq {seq}: {packet_info}")
                continue
        
            if (seq not in self.acked_packets and 
                current_time - sent_time > self.timeout_interval):
                timed_out.append(seq)
            
        return timed_out
    
    def should_retransmit(self) -> bool:
        """检查是否应该触发快速重传"""
        return self.dup_ack_count >= 3 and self.state != "fast_recovery"
    
    def get_packets_for_retransmit(self) -> List[tuple]:
        """获取需要重传的数据包（快速重传）- 返回完整信息"""
        if self.should_retransmit() and self.last_dup_ack in self.sent_packets:
            seq = self.last_dup_ack
            packet_info = self.sent_packets[seq]
            # 获取包数据
            if len(packet_info) == 4:
                packet_data, sent_time, is_retransmit, is_last = packet_info
            else:
                packet_data, sent_time, is_retransmit = packet_info
                # 如果没有保存is_last，从packets列表判断
                is_last = (seq == len(self.packets))
            return [(seq, packet_data, is_last)]
        return []

    def get_next_packet_to_send(self) -> Optional[tuple]:
        if self.next_seq > len(self.packets):
            return None
        packet_data = self.packets[self.next_seq - 1]
        is_last = (self.next_seq == len(self.packets))
        return self.next_seq, packet_data, is_last
    
    def on_data_received(self, seq: int, data: bytes, is_last: bool) -> None:
        """处理接收到的数据包，支持乱序包缓存"""
        self.last_activity = time.time()
        self.last_data_time = time.time()
        
        # 记录接收到的最大序列号
        if seq > self.max_received_seq:
            self.max_received_seq = seq
        
        # 处理 is_last 标志 - 关键修改：不立即检查完成
        if is_last:
            self.has_received_last_flag = True
            # 只记录期望的最后一个包序列号，不立即设置last_packet_received
            if self.expected_last_seq is None or seq > self.expected_last_seq:
                self.expected_last_seq = seq
                logging.info(f"Received packet with LAST flag: seq={seq} (total_received={len(self.received_packets)})")
        
        # 如果是期望的下一个包（按序到达）
        if seq == self.next_seq:
            self.received_packets[seq] = data
            self.next_seq += 1
            
            # 检查乱序缓冲区中是否有连续的包
            while self.next_seq in self.out_of_order_buffer:
                buffered_data = self.out_of_order_buffer.pop(self.next_seq)
                self.received_packets[self.next_seq] = buffered_data
                self.next_seq += 1
            
            logging.debug(f"Received in-order packet {seq}, next_seq={self.next_seq}")
        
        else:
            # 乱序包：先检查是否在合理范围内
            if seq < self.next_seq:
                # 重复包或过期的包，如果还没收到就保存
                if seq not in self.received_packets:
                    self.received_packets[seq] = data
                    logging.debug(f"Received duplicate/old packet {seq} (next_seq={self.next_seq})")
                else:
                    logging.debug(f"Ignoring duplicate packet {seq}")
            elif seq <= self.max_received_seq + 100:  # 合理的未来包范围
                # 缓存乱序包
                self.out_of_order_buffer[seq] = data
                logging.debug(f"Buffered out-of-order packet {seq} (next_seq={self.next_seq}, buffer_size={len(self.out_of_order_buffer)})")
            else:
                # 序列号跳跃太大，可能是错误，但依然缓存
                self.out_of_order_buffer[seq] = data
                logging.warning(f"Received packet with seq={seq} far beyond next_seq={self.next_seq}")
        
        # 定期记录进度
        received_count = len(self.received_packets)
        if is_last or (seq % 50 == 0 and seq > 0) or (received_count % 50 == 0 and received_count > 0):
            logging.debug(f"Download progress: {received_count} packets received, "
                         f"next_seq={self.next_seq}, buffered={len(self.out_of_order_buffer)}")
    
    def is_complete(self) -> bool:
        """检查下载是否完成 - 修改为更宽松的检查"""
        if self.is_upload:
            return self.last_packet_sent and (len(self.acked_packets) == len(self.packets))
        else:
            # 情况1：如果还没有收到LAST标志，肯定没完成
            if not self.has_received_last_flag:
                return False
            
            # 情况2：不知道最后一个包的序列号
            if self.expected_last_seq is None:
                return False
            
            last_seq = self.expected_last_seq
            
            # 情况3：检查是否收到了1到last_seq的所有包
            missing_count = 0
            missing_packets = []
            
            for seq in range(1, last_seq + 1):
                if seq not in self.received_packets:
                    missing_count += 1
                    missing_packets.append(seq)
            
            # 情况3a：所有包都收到了
            if missing_count == 0:
                self.last_packet_received = True
                logging.info(f"Download COMPLETE: All {last_seq} packets received")
                return True
            
            # 情况3b：有少量包缺失
            max_allowed_missing = max(5, int(last_seq * 0.05))  # 最多5个或5%的包缺失
            if missing_count <= max_allowed_missing:
                # 检查是否已经等待足够长时间让重传发生
                current_time = time.time()
                time_since_last_data = current_time - self.last_data_time
                
                if time_since_last_data > 10.0:  # 等待10秒重传
                    # 如果等待时间足够长，认为完成（少量包可能永久丢失）
                    logging.warning(f"Download NEARLY COMPLETE: {len(self.received_packets)}/{last_seq} packets, "
                                  f"missing {missing_count} packets after {time_since_last_data:.1f}s wait")
                    
                    # 记录具体缺失的包（如果不多）
                    if missing_count <= 10:
                        logging.warning(f"Missing packets: {missing_packets}")
                    
                    # 如果缺失的包很少，且等待时间足够，认为完成
                    if time_since_last_data > 15.0:  # 等待15秒
                        self.last_packet_received = True
                        return True
                    else:
                        return False
                else:
                    # 继续等待重传
                    return False
            
            # 情况4：缺失太多包
            else:
                # 检查是否长时间没有活动（可能peer崩溃）
                current_time = time.time()
                if current_time - self.last_activity > 20.0:
                    logging.warning(f"Download STALLED: Only {len(self.received_packets)}/{last_seq} packets "
                                  f"received, {missing_count} missing, no activity for 20s")
                    return False
                
                return False
    
    def _check_sequence_continuity_up_to(self, max_seq: int) -> bool:
        """检查序列连续性（主要用于调试）"""
        if max_seq <= 0:
            return False
        
        missing_count = 0
        for seq in range(1, max_seq + 1):
            if seq not in self.received_packets:
                missing_count += 1
                logging.debug(f"Missing packet {seq} in sequence 1-{max_seq}")
        
        if missing_count == 0:
            logging.info(f"All packets from 1 to {max_seq} are continuous")
            return True
        else:
            logging.info(f"Sequence 1-{max_seq} has {missing_count} missing packets")
            return False

    def _check_sequence_continuity(self) -> bool:
        """检查已收到包的连续性"""
        if not self.received_packets:
            return False
        
        sorted_seqs = sorted(self.received_packets.keys())
        
        # 如果有期望的最后一个包，检查到那个位置
        if self.expected_last_seq:
            return self._check_sequence_continuity_up_to(self.expected_last_seq)
        
        # 否则检查已收到包的连续性
        expected_seq = min(sorted_seqs)
        for seq in sorted_seqs:
            if seq != expected_seq:
                return False
            expected_seq += 1
        return True

    def assemble_chunk(self) -> bytes:
        """组装完整的chunk数据"""
        if not self.is_complete():
            raise ValueError("Cannot assemble incomplete chunk")
        
        # 确保我们按顺序组装包
        sorted_seqs = sorted(self.received_packets.keys())
        
        # 如果知道最后一个包的seq，确保我们有1到那个seq的所有包
        if self.expected_last_seq:
            for seq in range(1, self.expected_last_seq + 1):
                if seq not in self.received_packets:
                    raise ValueError(f"Missing packet {seq} for assembly (expected_last_seq={self.expected_last_seq})")
        
        sorted_packets = [self.received_packets[seq] for seq in sorted_seqs]
        total_size = sum(len(packet) for packet in sorted_packets)
        logging.info(f"Assembling chunk: {len(sorted_packets)} packets, total size: {total_size} bytes")
        
        chunk_data = b''.join(sorted_packets)
        return chunk_data

class PeerState:
    def __init__(self, context: PeerContext):
        self.context = context
        self.local_chunks: Dict[bytes, bytes] = {}
        self.peer_chunk_map: Dict[AddressType, Set[bytes]] = defaultdict(set)
        self.active_uploads: Dict[AddressType, bytes] = {}
        self.known_peers: List[AddressType] = []
        
        # RDT会话管理 - 统一使用peer_addr作为键
        self.upload_sessions: Dict[AddressType, TransferSession] = {}
        self.download_sessions: Dict[AddressType, TransferSession] = {}  # 改为使用peer_addr作为键
        
        self._initialize_state()
    
    def _initialize_state(self):
        """Initialize state"""
        # 1. Initialize local chunks - Note: PeerContext.has_chunks is {hex_str: bytes}
        if hasattr(self.context, 'has_chunks') and self.context.has_chunks:
            # Convert hex string keys to bytes
            for hex_hash, chunk_data in self.context.has_chunks.items():
                if isinstance(hex_hash, str):
                    # Hex string to bytes
                    chunk_hash_bytes = bytes.fromhex(hex_hash)
                    self.local_chunks[chunk_hash_bytes] = chunk_data
                else:
                    # If already bytes, use directly
                    self.local_chunks[hex_hash] = chunk_data
        
        # 2. Initialize known peer list
        # PeerContext.peers is list[list[str]], each sublist is [id_str, ip, port_str]
        if hasattr(self.context, 'peers') and self.context.peers:
            for peer_info in self.context.peers:
                if len(peer_info) >= 3:
                    peer_id = int(peer_info[0])
                    peer_ip = peer_info[1]
                    peer_port = int(peer_info[2])
                    
                    # Exclude self
                    if peer_id != self.context.identity:
                        self.known_peers.append((peer_ip, peer_port))
    
    def can_accept_upload(self) -> bool:
        """Check if can accept new upload requests"""
        return len(self.active_uploads) < self.context.max_conn
    
    def start_upload(self, peer_addr: AddressType, chunk_hash: bytes) -> bool:
        """Start upload session"""
        if self.can_accept_upload():
            self.active_uploads[peer_addr] = chunk_hash
            return True
        return False
    
    def stop_upload(self, peer_addr: AddressType):
        """Stop upload session"""
        self.active_uploads.pop(peer_addr, None)
    
    def add_peer_chunks(self, peer_addr: AddressType, chunk_hashes: List[bytes]):
        """Record chunks owned by peer"""
        self.peer_chunk_map[peer_addr].update(chunk_hashes)
    
    def get_peers_with_chunk(self, chunk_hash: bytes) -> List[AddressType]:
        """Get list of peers that have the specified chunk"""
        return [peer for peer, chunks in self.peer_chunk_map.items() 
                if chunk_hash in chunks]
    
    def start_upload_session(self, peer_addr: AddressType, chunk_hash: bytes, chunk_data: bytes) -> bool:
        """开始上传会话"""
        if not self.can_accept_upload():
            return False
            
        session = TransferSession(peer_addr, chunk_hash, chunk_data, is_upload=True)
        self.upload_sessions[peer_addr] = session
        self.active_uploads[peer_addr] = chunk_hash
        return True
    
    def start_download_session(self, peer_addr: AddressType, chunk_hash: bytes) -> TransferSession:
        """开始下载会话 - 确保只有一个会话"""
        # 如果已有这个peer的会话，先清理
        if peer_addr in self.download_sessions:
            old_session = self.download_sessions[peer_addr]
            logging.warning(f"Replacing existing download session for {peer_addr}")
            del self.download_sessions[peer_addr]
        
        # 创建新会话
        session = TransferSession(peer_addr, chunk_hash, is_upload=False)
        self.download_sessions[peer_addr] = session
        logging.info(f"Started download session for {peer_addr}, chunk {chunk_hash.hex()[:16]}...")
        return session
    
    def get_download_session(self, peer_addr: AddressType) -> Optional[TransferSession]:
        """获取下载会话"""
        return self.download_sessions.get(peer_addr)
    
    def has_active_session_with_peer(self, peer_addr: AddressType) -> bool:
        """检查是否与指定peer有活跃会话"""
        return peer_addr in self.download_sessions

    def get_upload_session(self, peer_addr: AddressType) -> Optional[TransferSession]:
        """获取上传会话"""
        return self.upload_sessions.get(peer_addr)
    
    def get_download_session_by_peer(self, peer_addr: AddressType) -> Optional[TransferSession]:
        """通过对端地址获取下载会话"""
        return self.download_sessions.get(peer_addr)
    
    def remove_upload_session(self, peer_addr: AddressType) -> None:
        """移除上传会话 - 确保完全清理"""
        logging.info(f"=== remove_upload_session for {peer_addr} ===")
    
        # 记录清理前的状态
        had_upload = peer_addr in self.upload_sessions
        had_active = peer_addr in self.active_uploads
    
        if had_upload:
            session = self.upload_sessions[peer_addr]
            chunk_hash = session.chunk_hash.hex()[:16] if hasattr(session, 'chunk_hash') else 'unknown'
            logging.info(f"Removing upload session for {peer_addr}, chunk {chunk_hash}")
            del self.upload_sessions[peer_addr]
        else:
            logging.debug(f"No upload session found for {peer_addr}")
    
        if had_active:
            chunk_hash = self.active_uploads[peer_addr]
            if isinstance(chunk_hash, bytes):
                chunk_hash = chunk_hash.hex()[:16]
            logging.info(f"Removing active upload for {peer_addr}, chunk {chunk_hash}")
            del self.active_uploads[peer_addr]
        else:
            logging.debug(f"No active upload found for {peer_addr}")
    
        # 确保连接被释放，允许新的上传
        logging.info(f"Upload connection released for {peer_addr}")
        logging.info(f"Current active_uploads: {len(self.active_uploads)}")
        logging.info(f"Current upload_sessions: {len(self.upload_sessions)}")
        logging.info("=== remove_upload_session END ===")

    def remove_download_session(self, peer_addr: AddressType) -> None:
        """移除下载会话"""
        if peer_addr in self.download_sessions:
            del self.download_sessions[peer_addr]
            logging.debug(f"Removed download session for {peer_addr}")
    
    def remove_download_session_by_peer(self, peer_addr: AddressType) -> None:
        """通过对端地址移除下载会话"""
        if peer_addr in self.download_sessions:
            del self.download_sessions[peer_addr]
    
    def get_all_sessions(self) -> List[TransferSession]:
        """获取所有活跃会话"""
        sessions = list(self.upload_sessions.values()) + list(self.download_sessions.values())
        return sessions
