#!/usr/bin/env python3
"""
DCC Internet P2P Blockchain Chat
Sistema de chat distribuído com verificação por blockchain
"""

import socket
import threading
import struct
import hashlib
import time
import random
import sys
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum

# Constantes
PORT = 51511
PEER_REQUEST_INTERVAL = 5  # segundos
MAX_CHAT_LENGTH = 255
HASH_PREFIX_ZEROS = 2
MD5_SIZE = 16
VERIFICATION_CODE_SIZE = 16
HISTORY_VALIDATION_SIZE = 20

class MessageType(IntEnum):
    """Tipos de mensagens do protocolo"""
    PEER_REQUEST = 0x1
    PEER_LIST = 0x2
    ARCHIVE_REQUEST = 0x3
    ARCHIVE_RESPONSE = 0x4

@dataclass
class Chat:
    """Representa um chat no histórico"""
    text: str
    verification_code: bytes
    md5_hash: bytes
    
    def to_bytes(self) -> bytes:
        """Converte o chat para bytes"""
        text_bytes = self.text.encode('ascii')
        return (struct.pack('B', len(text_bytes)) + 
                text_bytes + 
                self.verification_code + 
                self.md5_hash)
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> Tuple['Chat', int]:
        """Cria um chat a partir de bytes"""
        text_length = struct.unpack('B', data[offset:offset+1])[0]
        offset += 1
        
        text = data[offset:offset+text_length].decode('ascii')
        offset += text_length
        
        verification_code = data[offset:offset+VERIFICATION_CODE_SIZE]
        offset += VERIFICATION_CODE_SIZE
        
        md5_hash = data[offset:offset+MD5_SIZE]
        offset += MD5_SIZE
        
        return cls(text, verification_code, md5_hash), offset

class P2PChat:
    """Classe principal do sistema de chat P2P"""
    
    def __init__(self, initial_peer_ip: Optional[str] = None, bind_ip: Optional[str] = None):
        self.bind_ip = bind_ip  # IP específico para bind
        self.my_ip = bind_ip if bind_ip else self._get_local_ip()
        self.peers: Set[str] = set()
        self.connections: Dict[str, socket.socket] = {}
        self.chat_history: List[Chat] = []
        self.running = False
        self.server_socket = None
        self.initial_peer_ip = initial_peer_ip
        
        # Locks para thread safety
        self.peers_lock = threading.Lock()
        self.connections_lock = threading.Lock()
        self.history_lock = threading.Lock()
    
    def _get_local_ip(self) -> str:
        """Obtém o IP local"""
        try:
            # Conecta a um endereço externo para descobrir o IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def start(self):
        """Inicia o sistema P2P"""
        self.running = True
        
        # Inicia servidor para receber conexões
        self._start_server()
        
        # Conecta ao par inicial se fornecido
        if self.initial_peer_ip:
            print(f"Conectando ao peer inicial: {self.initial_peer_ip}")
            if self._connect_to_peer(self.initial_peer_ip):
                # Solicita histórico inicial
                time.sleep(1)  # Aguarda estabilização da conexão
                self._request_history_from_peers()
        
        # Inicia threads auxiliares
        threading.Thread(target=self._peer_discovery_loop, daemon=True).start()
        
        print(f"Sistema P2P iniciado no IP {self.my_ip}:{PORT}")
        print("Digite 'help' para ver os comandos disponíveis")
        
        # Loop principal de interface
        self._main_loop()
    
    def _start_server(self):
        """Inicia o servidor para receber conexões"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind to specific IP instead of all interfaces
            bind_address = self.bind_ip if self.bind_ip else ''
            self.server_socket.bind((bind_address, PORT))
            self.server_socket.listen(10)
            threading.Thread(target=self._accept_connections, daemon=True).start()
        except Exception as e:
            print(f"Erro ao iniciar servidor: {e}")
            sys.exit(1)
    
    def _accept_connections(self):
        """Aceita conexões de entrada"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                peer_ip = addr[0]
                
                with self.connections_lock:
                    self.connections[peer_ip] = client_socket
                
                with self.peers_lock:
                    self.peers.add(peer_ip)
                
                # Inicia thread para lidar com mensagens deste peer
                threading.Thread(target=self._handle_peer_messages, 
                               args=(peer_ip, client_socket), daemon=True).start()
                
                print(f"Nova conexão aceita de {peer_ip}")
                
            except Exception as e:
                if self.running:
                    print(f"Erro ao aceitar conexão: {e}")
    
    def _connect_to_peer(self, peer_ip: str) -> bool:
        """Conecta a um peer específico"""
        if peer_ip == self.my_ip:
            return False
        
        with self.connections_lock:
            if peer_ip in self.connections:
                return True
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, PORT))
            
            with self.connections_lock:
                self.connections[peer_ip] = sock
            
            with self.peers_lock:
                self.peers.add(peer_ip)
            
            # Inicia thread para lidar com mensagens deste peer
            threading.Thread(target=self._handle_peer_messages, 
                           args=(peer_ip, sock), daemon=True).start()
            
            print(f"Conectado ao peer {peer_ip}")
            return True
            
        except Exception as e:
            print(f"Erro ao conectar com {peer_ip}: {e}")
            return False
    
    def _request_history_from_peers(self):
        """Solicita histórico de todos os peers conectados"""
        with self.connections_lock:
            peer_connections = list(self.connections.items())
        
        if not peer_connections:
            print("Nenhum peer conectado para solicitar histórico")
            return
        
        print(f"Solicitando histórico de {len(peer_connections)} peer(s)...")
        
        for peer_ip, sock in peer_connections:
            try:
                # Envia ArchiveRequest
                message = struct.pack('B', MessageType.ARCHIVE_REQUEST)
                sock.send(message)
                print(f"Solicitação de histórico enviada para {peer_ip}")
            except Exception as e:
                print(f"Erro ao solicitar histórico de {peer_ip}: {e}")
                self._disconnect_peer(peer_ip)
    
    def _validate_current_history(self):
        """Valida o histórico atual"""
        with self.history_lock:
            if not self.chat_history:
                print("Histórico vazio - válido")
                return
            
            if self._validate_history(self.chat_history):
                print(f"Histórico válido ({len(self.chat_history)} mensagens)")
            else:
                print("Histórico inválido!")
    
    def _show_status(self):
        """Mostra status do sistema"""
        with self.peers_lock:
            peer_count = len(self.peers)
        
        with self.connections_lock:
            connection_count = len(self.connections)
        
        with self.history_lock:
            history_count = len(self.chat_history)
        
        print(f"\nStatus do sistema:")
        print(f"  Meu IP: {self.my_ip}:{PORT}")
        print(f"  Peers conhecidos: {peer_count}")
        print(f"  Conexões ativas: {connection_count}")
        print(f"  Mensagens no histórico: {history_count}")
        print(f"  Sistema rodando: {'Sim' if self.running else 'Não'}")

    def _handle_peer_messages(self, peer_ip: str, sock: socket.socket):
        """Lida com mensagens de um peer específico"""
        try:
            while self.running:
                # Lê o tipo da mensagem (1 byte)
                msg_type_data = sock.recv(1)
                if not msg_type_data:
                    break
                
                msg_type = struct.unpack('B', msg_type_data)[0]
                
                if msg_type == MessageType.PEER_REQUEST:
                    self._handle_peer_request(peer_ip, sock)
                elif msg_type == MessageType.PEER_LIST:
                    self._handle_peer_list(peer_ip, sock)
                elif msg_type == MessageType.ARCHIVE_REQUEST:
                    self._handle_archive_request(peer_ip, sock)
                elif msg_type == MessageType.ARCHIVE_RESPONSE:
                    self._handle_archive_response(peer_ip, sock)
                else:
                    print(f"Tipo de mensagem desconhecido: {msg_type}")
                    
        except Exception as e:
            print(f"Erro ao lidar com mensagens de {peer_ip}: {e}")
        finally:
            self._disconnect_peer(peer_ip)
    
    def _disconnect_peer(self, peer_ip: str):
        """Desconecta um peer"""
        with self.connections_lock:
            if peer_ip in self.connections:
                try:
                    self.connections[peer_ip].close()
                except:
                    pass
                del self.connections[peer_ip]
        
        with self.peers_lock:
            self.peers.discard(peer_ip)
        
        print(f"Peer {peer_ip} desconectado")
    
    def _peer_discovery_loop(self):
        """Loop de descoberta de peers (executa a cada 5 segundos)"""
        while self.running:
            time.sleep(PEER_REQUEST_INTERVAL)
            
            with self.connections_lock:
                peer_connections = list(self.connections.items())
            
            for peer_ip, sock in peer_connections:
                try:
                    # Envia PeerRequest
                    self._send_peer_request(sock)
                except Exception as e:
                    print(f"Erro ao enviar PeerRequest para {peer_ip}: {e}")
                    self._disconnect_peer(peer_ip)
    
    def _send_peer_request(self, sock: socket.socket):
        """Envia uma mensagem PeerRequest"""
        message = struct.pack('B', MessageType.PEER_REQUEST)
        sock.send(message)
    
    def _handle_peer_request(self, peer_ip: str, sock: socket.socket):
        """Lida com uma mensagem PeerRequest"""
        # Responde com PeerList
        with self.peers_lock:
            peer_list = list(self.peers)
        
        # Adiciona o próprio IP à lista
        if self.my_ip not in peer_list:
            peer_list.append(self.my_ip)
        
        # Constrói a mensagem PeerList
        message = struct.pack('B', MessageType.PEER_LIST)
        message += struct.pack('!I', len(peer_list))
        
        for ip in peer_list:
            # Converte IP para inteiro de 4 bytes
            ip_parts = ip.split('.')
            ip_int = struct.pack('!BBBB', int(ip_parts[0]), int(ip_parts[1]), 
                               int(ip_parts[2]), int(ip_parts[3]))
            message += ip_int
        
        sock.send(message)
    
    def _handle_peer_list(self, peer_ip: str, sock: socket.socket):
        """Lida com uma mensagem PeerList"""
        # Lê o número de peers
        count_data = sock.recv(4)
        if len(count_data) < 4:
            return
        
        peer_count = struct.unpack('!I', count_data)[0]
        
        # Lê os IPs dos peers
        new_peers = []
        for _ in range(peer_count):
            ip_data = sock.recv(4)
            if len(ip_data) < 4:
                return
            
            ip_parts = struct.unpack('!BBBB', ip_data)
            ip_str = '.'.join(str(part) for part in ip_parts)
            new_peers.append(ip_str)
        
        # Conecta aos novos peers
        for new_peer_ip in new_peers:
            if new_peer_ip != self.my_ip:
                self._connect_to_peer(new_peer_ip)
    
    def _handle_archive_request(self, peer_ip: str, sock: socket.socket):
        """Lida com uma mensagem ArchiveRequest"""
        # Responde com ArchiveResponse
        with self.history_lock:
            history_data = self._serialize_history()
        
        message = struct.pack('B', MessageType.ARCHIVE_RESPONSE)
        message += struct.pack('!I', len(self.chat_history))
        message += history_data
        
        sock.send(message)
    
    def _handle_archive_response(self, peer_ip: str, sock: socket.socket):
        """Lida com uma mensagem ArchiveResponse"""
        # Lê o número de chats
        count_data = sock.recv(4)
        if len(count_data) < 4:
            return
        
        chat_count = struct.unpack('!I', count_data)[0]
        
        # Lê os dados do histórico
        history_data = b''
        expected_size = self._calculate_history_size(chat_count)
        
        while len(history_data) < expected_size:
            chunk = sock.recv(expected_size - len(history_data))
            if not chunk:
                return
            history_data += chunk
        
        # Deserializa o histórico
        new_history = self._deserialize_history(history_data)
        
        # Valida o histórico
        if self._validate_history(new_history):
            with self.history_lock:
                if len(new_history) > len(self.chat_history):
                    self.chat_history = new_history
                    print(f"Histórico atualizado com {len(new_history)} chats")
    
    def _serialize_history(self) -> bytes:
        """Serializa o histórico de chats"""
        data = b''
        for chat in self.chat_history:
            data += chat.to_bytes()
        return data
    
    def _deserialize_history(self, data: bytes) -> List[Chat]:
        """Deserializa o histórico de chats"""
        history = []
        offset = 0
        
        while offset < len(data):
            chat, offset = Chat.from_bytes(data, offset)
            history.append(chat)
        
        return history
    
    def _calculate_history_size(self, chat_count: int) -> int:
        """Calcula o tamanho esperado do histórico (estimativa)"""
        # Estimativa baseada no tamanho médio dos chats
        # Na prática, seria melhor ler dinamicamente
        return chat_count * (1 + 50 + VERIFICATION_CODE_SIZE + MD5_SIZE)
    
    def _validate_history(self, history: List[Chat]) -> bool:
        """Valida um histórico de chats recursivamente"""
        if not history:
            return True
        
        # Validação recursiva - valida o histórico sem a última mensagem primeiro
        if len(history) > 1:
            if not self._validate_history(history[:-1]):
                return False
        
        # Valida a última mensagem
        return self._validate_last_chat(history)
    
    def _validate_last_chat(self, history: List[Chat]) -> bool:
        """Valida a última mensagem do histórico"""
        if not history:
            return True
        
        last_chat = history[-1]
        
        # Verifica se o hash MD5 começa com dois bytes zero
        if last_chat.md5_hash[:HASH_PREFIX_ZEROS] != b'\x00' * HASH_PREFIX_ZEROS:
            return False
        
        # Calcula o hash MD5 esperado
        expected_hash = self._calculate_chat_hash(history)
        
        # Compara com o hash armazenado
        return last_chat.md5_hash == expected_hash
    
    def _calculate_chat_hash(self, history: List[Chat]) -> bytes:
        """Calcula o hash MD5 para validação do último chat"""
        if not history:
            return b'\x00' * MD5_SIZE
        
        # Pega os últimos 20 chats (ou todos se houver menos de 20)
        chats_to_hash = history[-HISTORY_VALIDATION_SIZE:]
        
        # Constrói a sequência S para hash
        sequence = b''
        for i, chat in enumerate(chats_to_hash):
            if i == len(chats_to_hash) - 1:
                # Para o último chat, não inclui o hash MD5
                sequence += struct.pack('B', len(chat.text))
                sequence += chat.text.encode('ascii')
                sequence += chat.verification_code
            else:
                # Para outros chats, inclui tudo
                sequence += chat.to_bytes()
        
        return hashlib.md5(sequence).digest()
    
    def _main_loop(self):
        """Loop principal da interface"""
        while self.running:
            try:
                command = input("> ").strip().lower()
                
                if command == 'help':
                    self._show_help()
                elif command == 'peers':
                    self._show_peers()
                elif command == 'history':
                    self._show_history()
                elif command == 'request':
                    self._request_history_from_peers()
                elif command == 'validate':
                    self._validate_current_history()
                elif command == 'status':
                    self._show_status()
                elif command.startswith('connect '):
                    ip = command[8:].strip()
                    self._connect_to_peer(ip)
                elif command.startswith('chat '):
                    message = command[5:].strip()
                    self._send_chat(message)
                elif command == 'quit':
                    self._shutdown()
                    break
                else:
                    print("Comando desconhecido. Digite 'help' para ver os comandos.")
                    
            except KeyboardInterrupt:
                self._shutdown()
                break
            except EOFError:
                self._shutdown()
                break
    
    def _show_help(self):
        """Mostra a ajuda"""
        print("\nComandos disponíveis:")
        print("  help              - Mostra esta ajuda")
        print("  peers             - Lista peers conectados")
        print("  history           - Mostra histórico de chats")
        print("  request           - Solicita histórico de todos os peers")
        print("  connect <ip>      - Conecta a um peer específico")
        print("  chat <mensagem>   - Envia uma mensagem de chat")
        print("  validate          - Valida o histórico atual")
        print("  status            - Mostra status do sistema")
        print("  quit              - Encerra o programa")
    
    def _show_peers(self):
        """Mostra peers conectados"""
        with self.peers_lock:
            if self.peers:
                print(f"\nPeers conectados ({len(self.peers)}):")
                for peer in sorted(self.peers):
                    print(f"  {peer}")
            else:
                print("\nNenhum peer conectado")
    
    def _show_history(self):
        """Mostra histórico de chats"""
        with self.history_lock:
            if self.chat_history:
                print(f"\nHistórico de chats ({len(self.chat_history)} mensagens):")
                for i, chat in enumerate(self.chat_history):
                    print(f"  {i+1}: {chat.text}")
            else:
                print("\nNenhum chat no histórico")
    
    def _send_chat(self, message: str):
        """Envia uma mensagem de chat"""
        if len(message) > MAX_CHAT_LENGTH:
            print(f"Mensagem muito longa (máximo {MAX_CHAT_LENGTH} caracteres)")
            return
        
        # Verifica se a mensagem contém apenas caracteres alfanuméricos e espaços
        if not all(c.isalnum() or c.isspace() for c in message):
            print("Mensagem deve conter apenas caracteres alfanuméricos e espaços")
            return
        
        print(f"Minerando chat: '{message}'...")
        
        # Minera o chat em thread separada para não bloquear a interface
        threading.Thread(target=self._mine_and_send_chat, args=(message,), daemon=True).start()
    
    def _mine_and_send_chat(self, message: str):
        """Minera um chat e o envia para todos os peers"""
        try:
            # Minera o chat
            new_chat = self._mine_chat(message)
            
            if new_chat:
                # Adiciona ao histórico local
                with self.history_lock:
                    self.chat_history.append(new_chat)
                    print(f"Chat minerado e adicionado ao histórico: '{message}'")
                
                # Envia para todos os peers
                self._broadcast_history()
            else:
                print("Erro ao minerar o chat")
                
        except Exception as e:
            print(f"Erro ao minerar chat: {e}")
    
    def _mine_chat(self, message: str) -> Optional[Chat]:
        """Minera um chat encontrando um código verificador válido"""
        start_time = time.time()
        attempts = 0
        
        while True:
            attempts += 1
            
            # Gera código verificador aleatório
            verification_code = bytes([random.randint(0, 255) for _ in range(VERIFICATION_CODE_SIZE)])
            
            # Cria chat temporário
            temp_chat = Chat(message, verification_code, b'\x00' * MD5_SIZE)
            
            # Cria histórico temporário
            with self.history_lock:
                temp_history = self.chat_history + [temp_chat]
            
            # Calcula hash
            calculated_hash = self._calculate_chat_hash(temp_history)
            
            # Verifica se o hash começa com dois bytes zero
            if calculated_hash[:HASH_PREFIX_ZEROS] == b'\x00' * HASH_PREFIX_ZEROS:
                # Sucesso! Cria o chat final
                final_chat = Chat(message, verification_code, calculated_hash)
                
                elapsed = time.time() - start_time
                print(f"Chat minerado com sucesso! Tentativas: {attempts}, Tempo: {elapsed:.2f}s")
                return final_chat
            
            # Mostra progresso a cada 10000 tentativas
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"Minerando... Tentativas: {attempts}, Taxa: {rate:.0f}/s")
    
    def _broadcast_history(self):
        """Envia o histórico atual para todos os peers"""
        with self.history_lock:
            history_data = self._serialize_history()
            chat_count = len(self.chat_history)
        
        message = struct.pack('B', MessageType.ARCHIVE_RESPONSE)
        message += struct.pack('!I', chat_count)
        message += history_data
        
        with self.connections_lock:
            for peer_ip, sock in list(self.connections.items()):
                try:
                    sock.send(message)
                except Exception as e:
                    print(f"Erro ao enviar histórico para {peer_ip}: {e}")
                    self._disconnect_peer(peer_ip)
    
    def _shutdown(self):
        """Encerra o sistema"""
        print("\nEncerrando sistema...")
        self.running = False
        
        # Fecha todas as conexões
        with self.connections_lock:
            for sock in self.connections.values():
                try:
                    sock.close()
                except:
                    pass
        
        # Fecha servidor
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

def main():
    """Função principal"""
    initial_peer = None
    bind_ip = None
    
    if len(sys.argv) > 1:
        initial_peer = sys.argv[1]
    
    if len(sys.argv) > 2:
        bind_ip = sys.argv[2]
    
    chat_system = P2PChat(initial_peer, bind_ip)
    chat_system.start()

if __name__ == "__main__":
    main()
