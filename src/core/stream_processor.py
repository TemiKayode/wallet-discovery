"""
Stream Processing Module for Real-time Data Pipelines

This module provides real-time data processing capabilities for blockchain data,
including transaction streams, wallet activity monitoring, and live data analysis.
"""

import asyncio
import json
import logging
from typing import Dict, List, Callable, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import websockets
import aiohttp
from collections import deque
import threading
import queue
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class StreamEvent:
    """Represents a stream event with metadata"""
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]
    source: str
    chain: str
    priority: int = 1  # 1=low, 2=medium, 3=high, 4=critical


class DataPipeline:
    """Manages data flow through processing stages"""
    
    def __init__(self, max_buffer_size: int = 10000):
        self.max_buffer_size = max_buffer_size
        self.input_buffer = deque(maxlen=max_buffer_size)
        self.output_buffer = deque(maxlen=max_buffer_size)
        self.processing_stages: List[Callable] = []
        self.is_running = False
        self._lock = threading.Lock()
        
    def add_processing_stage(self, stage: Callable):
        """Add a processing stage to the pipeline"""
        self.processing_stages.append(stage)
        
    def add_event(self, event: StreamEvent):
        """Add an event to the input buffer"""
        with self._lock:
            if len(self.input_buffer) < self.max_buffer_size:
                self.input_buffer.append(event)
            else:
                logger.warning("Input buffer full, dropping oldest event")
                self.input_buffer.popleft()
                self.input_buffer.append(event)
                
    def process_pipeline(self):
        """Process events through all stages"""
        while self.is_running:
            try:
                if self.input_buffer:
                    with self._lock:
                        event = self.input_buffer.popleft()
                    
                    # Process through all stages
                    processed_event = event
                    for stage in self.processing_stages:
                        try:
                            processed_event = stage(processed_event)
                            if processed_event is None:
                                break  # Event filtered out
                        except Exception as e:
                            logger.error(f"Error in processing stage {stage.__name__}: {e}")
                            continue
                    
                    if processed_event:
                        with self._lock:
                            self.output_buffer.append(processed_event)
                            
            except Exception as e:
                logger.error(f"Pipeline processing error: {e}")
                
            asyncio.sleep(0.1)  # Small delay to prevent CPU spinning


class BlockchainStreamProcessor:
    """Handles real-time blockchain data streams"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.websocket_connections: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.subscribers: Dict[str, List[Callable]] = {}
        self.event_queue = asyncio.Queue()
        self.is_running = False
        
    async def start_ethereum_stream(self, websocket_url: str):
        """Start streaming Ethereum blockchain data"""
        try:
            async with websockets.connect(websocket_url) as websocket:
                self.websocket_connections['ethereum'] = websocket
                
                # Subscribe to new pending transactions
                subscribe_msg = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_subscribe",
                    "params": ["newPendingTransactions"]
                }
                await websocket.send(json.dumps(subscribe_msg))
                
                while self.is_running:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        
                        if 'params' in data and 'result' in data['params']:
                            tx_hash = data['params']['result']
                            event = StreamEvent(
                                event_type="new_transaction",
                                timestamp=datetime.utcnow(),
                                data={"tx_hash": tx_hash},
                                source="ethereum",
                                chain="ethereum",
                                priority=2
                            )
                            await self.event_queue.put(event)
                            
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("Ethereum WebSocket connection closed")
                        break
                        
        except Exception as e:
            logger.error(f"Ethereum stream error: {e}")
            
    async def start_bitcoin_stream(self, websocket_url: str):
        """Start streaming Bitcoin blockchain data"""
        try:
            async with websockets.connect(websocket_url) as websocket:
                self.websocket_connections['bitcoin'] = websocket
                
                # Subscribe to new blocks
                subscribe_msg = {
                    "action": "subscribe",
                    "topic": "blocks"
                }
                await websocket.send(json.dumps(subscribe_msg))
                
                while self.is_running:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        
                        if data.get('topic') == 'blocks':
                            event = StreamEvent(
                                event_type="new_block",
                                timestamp=datetime.utcnow(),
                                data=data.get('data', {}),
                                source="bitcoin",
                                chain="bitcoin",
                                priority=2
                            )
                            await self.event_queue.put(event)
                            
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("Bitcoin WebSocket connection closed")
                        break
                        
        except Exception as e:
            logger.error(f"Bitcoin stream error: {e}")
            
    async def process_stream_events(self):
        """Process events from the stream queue"""
        while self.is_running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Notify subscribers
                if event.event_type in self.subscribers:
                    for callback in self.subscribers[event.event_type]:
                        try:
                            await callback(event)
                        except Exception as e:
                            logger.error(f"Subscriber callback error: {e}")
                            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to specific event types"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
        
    async def start_streaming(self):
        """Start all blockchain streams"""
        self.is_running = True
        
        # Start stream processors
        tasks = [
            self.process_stream_events(),
            self.start_ethereum_stream(self.config.get_setting('ethereum_websocket_url')),
            self.start_bitcoin_stream(self.config.get_setting('bitcoin_websocket_url'))
        ]
        
        await asyncio.gather(*tasks)
        
    def stop_streaming(self):
        """Stop all blockchain streams"""
        self.is_running = False
        for websocket in self.websocket_connections.values():
            asyncio.create_task(websocket.close())


class RealTimeAnalyzer:
    """Real-time analysis of streaming data"""
    
    def __init__(self):
        self.transaction_patterns = {}
        self.wallet_activity = {}
        self.alert_triggers = {}
        
    def analyze_transaction(self, event: StreamEvent) -> Optional[StreamEvent]:
        """Analyze transaction events in real-time"""
        if event.event_type == "new_transaction":
            # Extract transaction data
            tx_data = event.data
            
            # Pattern recognition
            if self._detect_suspicious_pattern(tx_data):
                return StreamEvent(
                    event_type="suspicious_transaction",
                    timestamp=event.timestamp,
                    data=tx_data,
                    source=event.source,
                    chain=event.chain,
                    priority=4
                )
                
            # Update wallet activity
            self._update_wallet_activity(tx_data)
            
        return event
        
    def _detect_suspicious_pattern(self, tx_data: Dict) -> bool:
        """Detect suspicious transaction patterns"""
        # Implement pattern detection logic
        # This is a placeholder for actual implementation
        return False
        
    def _update_wallet_activity(self, tx_data: Dict):
        """Update wallet activity tracking"""
        # Implement wallet activity tracking
        pass
        
    def set_alert_trigger(self, condition: str, callback: Callable):
        """Set custom alert triggers"""
        self.alert_triggers[condition] = callback


class StreamManager:
    """Manages all streaming operations"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.stream_processor = BlockchainStreamProcessor(config_manager)
        self.data_pipeline = DataPipeline()
        self.real_time_analyzer = RealTimeAnalyzer()
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
    def setup_pipeline(self):
        """Setup the data processing pipeline"""
        # Add processing stages
        self.data_pipeline.add_processing_stage(self.real_time_analyzer.analyze_transaction)
        
        # Start pipeline processing
        self.data_pipeline.is_running = True
        self.thread_pool.submit(self.data_pipeline.process_pipeline)
        
    async def start_all_streams(self):
        """Start all streaming services"""
        try:
            self.setup_pipeline()
            await self.stream_processor.start_streaming()
        except Exception as e:
            logger.error(f"Failed to start streams: {e}")
            
    def stop_all_streams(self):
        """Stop all streaming services"""
        self.stream_processor.stop_streaming()
        self.data_pipeline.is_running = False
        self.thread_pool.shutdown(wait=True)
        
    def get_stream_status(self) -> Dict[str, Any]:
        """Get current stream status"""
        return {
            "ethereum_connected": "ethereum" in self.stream_processor.websocket_connections,
            "bitcoin_connected": "bitcoin" in self.stream_processor.websocket_connections,
            "pipeline_running": self.data_pipeline.is_running,
            "input_buffer_size": len(self.data_pipeline.input_buffer),
            "output_buffer_size": len(self.data_pipeline.output_buffer)
        }
