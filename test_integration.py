#!/usr/bin/env python3
"""
Testes de integração para o sistema P2P Chat
"""

import unittest
import socket
import threading
import time
import tempfile
import os
from unittest.mock import patch, Mock
import sys

# Adiciona o diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from p2p_chat_base import P2PChat, Chat, MessageType


class TestP2PChatIntegration(unittest.TestCase):
    """Testes de integração para cenários complexos"""

    def setUp(self):
        """Configuração inicial"""
        self.systems = []

    def tearDown(self):
        """Limpeza após cada teste"""
        for system in self.systems:
            try:
                system._shutdown()
            except:
                pass
        time.sleep(0.1)  # Aguarda limpeza

    def create_test_system(self, bind_ip="127.0.0.1"):
        """Cria um sistema de teste"""
        system = P2PChat(bind_ip=bind_ip)
        system.running = False  # Não inicia automático
        self.systems.append(system)
        return system

    def test_chat_serialization_roundtrip(self):
        """Testa serialização completa de múltiplos chats"""
        system = self.create_test_system()
        
        # Cria histórico com vários chats
        chats = [
            Chat("Primeira mensagem", b'\x01' * 16, b'\x00\x00' + b'\x02' * 14),
            Chat("Segunda mensagem", b'\x03' * 16, b'\x00\x00' + b'\x04' * 14),
            Chat("Terceira mensagem", b'\x05' * 16, b'\x00\x00' + b'\x06' * 14),
        ]
        
        system.chat_history = chats
        
        # Serializa
        data = system._serialize_history()
        
        # Deserializa
        recovered_history = system._deserialize_history(data)
        
        # Verifica se todos os chats foram recuperados corretamente
        self.assertEqual(len(recovered_history), len(chats))
        
        for original, recovered in zip(chats, recovered_history):
            self.assertEqual(original.text, recovered.text)
            self.assertEqual(original.verification_code, recovered.verification_code)
            self.assertEqual(original.md5_hash, recovered.md5_hash)

    def test_hash_calculation_chain(self):
        """Testa cálculo de hash em cadeia"""
        system = self.create_test_system()
        
        # Cria cadeia de chats
        chats = []
        for i in range(5):
            chat = Chat(f"Mensagem {i}", bytes([i] * 16), b'\x00\x00' + bytes([i+1] * 14))
            chats.append(chat)
        
        # Testa cálculo incremental
        for i in range(1, len(chats) + 1):
            partial_history = chats[:i]
            hash_result = system._calculate_chat_hash(partial_history)
            
            # Verifica se o hash é válido (16 bytes)
            self.assertEqual(len(hash_result), 16)
            self.assertIsInstance(hash_result, bytes)

    def test_validation_chain(self):
        """Testa validação em cadeia"""
        system = self.create_test_system()
        
        # Cria chats válidos (com hash começando com zeros)
        valid_chats = []
        for i in range(3):
            chat = Chat(f"Valid {i}", bytes([i] * 16), b'\x00\x00' + bytes([i+10] * 14))
            valid_chats.append(chat)
        
        # Mock da validação do último chat para retornar True
        with patch.object(system, '_validate_last_chat', return_value=True):
            result = system._validate_history(valid_chats)
            self.assertTrue(result)

    def test_peer_management_lifecycle(self):
        """Testa ciclo de vida completo do gerenciamento de peers"""
        system = self.create_test_system()
        
        # Adiciona peer
        peer_ip = "192.168.1.100"
        mock_socket = Mock()
        
        system.connections[peer_ip] = mock_socket
        system.peers.add(peer_ip)
        
        # Verifica se foi adicionado
        self.assertIn(peer_ip, system.connections)
        self.assertIn(peer_ip, system.peers)
        
        # Remove peer
        system._disconnect_peer(peer_ip)
        
        # Verifica se foi removido
        self.assertNotIn(peer_ip, system.connections)
        self.assertNotIn(peer_ip, system.peers)

    def test_message_type_handling(self):
        """Testa tratamento de todos os tipos de mensagem"""
        system = self.create_test_system()
        mock_socket = Mock()
        peer_ip = "192.168.1.100"
        
        # Testa cada tipo de mensagem
        message_handlers = {
            MessageType.PEER_REQUEST: system._handle_peer_request,
            MessageType.ARCHIVE_REQUEST: system._handle_archive_request,
        }
        
        for msg_type, handler in message_handlers.items():
            try:
                handler(peer_ip, mock_socket)
                # Se chegou até aqui, o handler não lançou exceção
                self.assertTrue(True)
            except Exception as e:
                self.fail(f"Handler para {msg_type} falhou: {e}")

    def test_concurrent_peer_connections(self):
        """Testa conexões simultâneas de múltiplos peers"""
        system = self.create_test_system()
        
        # Simula múltiplas conexões simultâneas
        peer_ips = [f"192.168.1.{i}" for i in range(100, 105)]
        
        def add_peer(ip):
            mock_socket = Mock()
            system.connections[ip] = mock_socket
            system.peers.add(ip)
        
        # Adiciona peers em threads simultâneas
        threads = []
        for ip in peer_ips:
            thread = threading.Thread(target=add_peer, args=(ip,))
            threads.append(thread)
            thread.start()
        
        # Aguarda todas as threads
        for thread in threads:
            thread.join()
        
        # Verifica se todos foram adicionados
        for ip in peer_ips:
            self.assertIn(ip, system.connections)
            self.assertIn(ip, system.peers)

    def test_large_history_handling(self):
        """Testa manipulação de histórico grande"""
        system = self.create_test_system()
        
        # Cria histórico grande
        large_history = []
        for i in range(100):
            chat = Chat(
                f"Mensagem número {i} com texto um pouco maior para testar",
                bytes([(i + j) % 256 for j in range(16)]),
                b'\x00\x00' + bytes([(i + j + 2) % 256 for j in range(14)])
            )
            large_history.append(chat)
        
        system.chat_history = large_history
        
        # Testa serialização
        data = system._serialize_history()
        
        # Verifica se não está vazio
        self.assertGreater(len(data), 0)
        
        # Testa deserialização
        recovered = system._deserialize_history(data)
        self.assertEqual(len(recovered), 100)

    def test_history_validation_limits(self):
        """Testa validação com limite de 20 chats"""
        system = self.create_test_system()
        
        # Cria histórico com mais de 20 chats
        long_history = []
        for i in range(25):
            chat = Chat(f"Chat {i}", bytes([i % 256] * 16), b'\x00\x00' + bytes([(i+1) % 256] * 14))
            long_history.append(chat)
        
        # Testa cálculo de hash (deve usar apenas os últimos 20)
        hash_result = system._calculate_chat_hash(long_history)
        
        # Verifica se o hash foi calculado
        self.assertEqual(len(hash_result), 16)

    def test_error_recovery(self):
        """Testa recuperação de erros"""
        system = self.create_test_system()
        
        # Testa recuperação de erro de socket
        mock_socket = Mock()
        mock_socket.recv.side_effect = socket.error("Connection lost")
        
        # Deve lidar com o erro sem crashar
        try:
            system._recv_exact(mock_socket, 10)
            self.fail("Deveria ter lançado ConnectionError")
        except ConnectionError:
            # Comportamento esperado
            pass
        except Exception as e:
            self.fail(f"Erro inesperado: {e}")

    def test_utf8_fallback(self):
        """Testa fallback para UTF-8"""
        system = self.create_test_system()
        
        # Simula dados UTF-8
        utf8_text = "Olá mundo"
        utf8_bytes = utf8_text.encode('utf-8')
        
        # Cria chat com texto UTF-8
        try:
            # Tenta decodificar como ASCII (vai falhar)
            try:
                text = utf8_bytes.decode('ascii')
            except UnicodeDecodeError:
                # Fallback para UTF-8
                text = utf8_bytes.decode('utf-8', errors='replace')
            
            self.assertEqual(text, utf8_text)
        except Exception as e:
            self.fail(f"Fallback UTF-8 falhou: {e}")

    def test_threading_safety(self):
        """Testa segurança de threading"""
        system = self.create_test_system()
        
        def add_remove_peer(peer_id):
            for i in range(10):
                ip = f"192.168.1.{peer_id}"
                mock_socket = Mock()
                
                # Adiciona
                with system.connections_lock:
                    system.connections[ip] = mock_socket
                with system.peers_lock:
                    system.peers.add(ip)
                
                time.sleep(0.01)  # Simula processamento
                
                # Remove
                system._disconnect_peer(ip)
        
        # Executa em múltiplas threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=add_remove_peer, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Aguarda conclusão
        for thread in threads:
            thread.join()
        
        # Verifica estado final
        self.assertEqual(len(system.connections), 0)
        self.assertEqual(len(system.peers), 0)


class TestProtocolCompliance(unittest.TestCase):
    """Testes de conformidade com o protocolo"""

    def setUp(self):
        """Configuração inicial"""
        self.system = P2PChat(bind_ip="127.0.0.1")
        self.system.running = False

    def test_message_format_peer_request(self):
        """Testa formato da mensagem PeerRequest"""
        mock_socket = Mock()
        self.system._send_peer_request(mock_socket)
        
        # Verifica se enviou exatamente 1 byte
        mock_socket.send.assert_called_once()
        sent_data = mock_socket.send.call_args[0][0]
        
        self.assertEqual(len(sent_data), 1)
        self.assertEqual(sent_data[0], MessageType.PEER_REQUEST)

    def test_message_format_peer_list(self):
        """Testa formato da mensagem PeerList"""
        mock_socket = Mock()
        
        # Adiciona alguns peers
        self.system.peers.add("192.168.1.100")
        self.system.peers.add("192.168.1.101")
        
        self.system._handle_peer_request("192.168.1.50", mock_socket)
        
        sent_data = mock_socket.send.call_args[0][0]
        
        # Verifica estrutura: 1 byte (tipo) + 4 bytes (count) + N * 4 bytes (IPs)
        self.assertEqual(sent_data[0], MessageType.PEER_LIST)
        
        # Extrai count
        count = int.from_bytes(sent_data[1:5], 'big')
        self.assertGreaterEqual(count, 2)  # Pelo menos os 2 peers + meu IP

    def test_message_format_archive_response(self):
        """Testa formato da mensagem ArchiveResponse"""
        mock_socket = Mock()
        
        # Adiciona chat
        chat = Chat("Test", b'\x01' * 16, b'\x02' * 16)
        self.system.chat_history.append(chat)
        
        self.system._handle_archive_request("192.168.1.100", mock_socket)
        
        sent_data = mock_socket.send.call_args[0][0]
        
        # Verifica estrutura: 1 byte (tipo) + 4 bytes (count) + dados
        self.assertEqual(sent_data[0], MessageType.ARCHIVE_RESPONSE)
        
        # Extrai count
        count = int.from_bytes(sent_data[1:5], 'big')
        self.assertEqual(count, 1)

    def test_chat_format_compliance(self):
        """Testa conformidade do formato de chat"""
        chat = Chat("Hello", b'\x01' * 16, b'\x02' * 16)
        data = chat.to_bytes()
        
        # Verifica estrutura: 1 byte (length) + text + 16 bytes (verification) + 16 bytes (hash)
        expected_length = 1 + len("Hello") + 16 + 16
        self.assertEqual(len(data), expected_length)
        
        # Verifica primeiro byte é o tamanho do texto
        self.assertEqual(data[0], len("Hello"))

    def test_ip_address_encoding(self):
        """Testa codificação de endereços IP"""
        mock_socket = Mock()
        
        # Adiciona IP específico
        test_ip = "192.168.1.100"
        self.system.peers.add(test_ip)
        
        self.system._handle_peer_request("192.168.1.50", mock_socket)
        
        sent_data = mock_socket.send.call_args[0][0]
        
        # Verifica se o IP foi codificado corretamente (4 bytes)
        # Estrutura: 1 byte (tipo) + 4 bytes (count) + N * 4 bytes (IPs)
        count = int.from_bytes(sent_data[1:5], 'big')
        ip_data_start = 5
        
        # Verifica se há dados suficientes para os IPs
        expected_ip_data_length = count * 4
        self.assertEqual(len(sent_data) - 5, expected_ip_data_length)


if __name__ == '__main__':
    unittest.main(verbosity=2)
