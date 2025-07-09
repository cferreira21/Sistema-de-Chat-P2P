#!/usr/bin/env python3
"""
Testes unitários para o sistema P2P Chat
"""

import unittest
import socket
import threading
import struct
import hashlib
import time
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Adiciona o diretório atual ao path para importar o módulo
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from p2p_chat_base import P2PChat, Chat, MessageType, PORT, MD5_SIZE, VERIFICATION_CODE_SIZE, HISTORY_VALIDATION_SIZE, HASH_PREFIX_ZEROS


class TestChat(unittest.TestCase):
    """Testes para a classe Chat"""

    def setUp(self):
        """Configuração inicial para cada teste"""
        self.text = "Hello World"
        self.verification_code = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        self.md5_hash = b'\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e'
        self.chat = Chat(self.text, self.verification_code, self.md5_hash)

    def test_chat_creation(self):
        """Testa criação de um objeto Chat"""
        self.assertEqual(self.chat.text, self.text)
        self.assertEqual(self.chat.verification_code, self.verification_code)
        self.assertEqual(self.chat.md5_hash, self.md5_hash)

    def test_to_bytes(self):
        """Testa serialização de Chat para bytes"""
        data = self.chat.to_bytes()
        
        expected_length = 1 + len(self.text) + VERIFICATION_CODE_SIZE + MD5_SIZE
        self.assertEqual(len(data), expected_length)
        
        # Verifica estrutura
        text_len = struct.unpack('B', data[0:1])[0]
        self.assertEqual(text_len, len(self.text))
        
        text_bytes = data[1:1+text_len]
        self.assertEqual(text_bytes.decode('ascii'), self.text)
        
        verification_bytes = data[1+text_len:1+text_len+VERIFICATION_CODE_SIZE]
        self.assertEqual(verification_bytes, self.verification_code)
        
        hash_bytes = data[1+text_len+VERIFICATION_CODE_SIZE:]
        self.assertEqual(hash_bytes, self.md5_hash)

    def test_from_bytes(self):
        """Testa deserialização de Chat a partir de bytes"""
        data = self.chat.to_bytes()
        reconstructed_chat, offset = Chat.from_bytes(data, 0)
        
        self.assertEqual(reconstructed_chat.text, self.chat.text)
        self.assertEqual(reconstructed_chat.verification_code, self.chat.verification_code)
        self.assertEqual(reconstructed_chat.md5_hash, self.chat.md5_hash)
        self.assertEqual(offset, len(data))

    def test_from_bytes_with_offset(self):
        """Testa deserialização com offset"""
        prefix = b'\x00\x00\x00'
        data = prefix + self.chat.to_bytes()
        
        reconstructed_chat, offset = Chat.from_bytes(data, 3)
        
        self.assertEqual(reconstructed_chat.text, self.chat.text)
        self.assertEqual(offset, len(data))

    def test_roundtrip_serialization(self):
        """Testa serialização ida e volta"""
        original = Chat("Test Message", b'\x01' * 16, b'\x02' * 16)
        data = original.to_bytes()
        reconstructed, _ = Chat.from_bytes(data, 0)
        
        self.assertEqual(original.text, reconstructed.text)
        self.assertEqual(original.verification_code, reconstructed.verification_code)
        self.assertEqual(original.md5_hash, reconstructed.md5_hash)


class TestP2PChat(unittest.TestCase):
    """Testes para a classe P2PChat"""

    def setUp(self):
        """Configuração inicial para cada teste"""
        self.chat_system = P2PChat(bind_ip="127.0.0.1")
        self.chat_system.running = False  # Evita iniciar threads automáticas

    def tearDown(self):
        """Limpeza após cada teste"""
        if hasattr(self.chat_system, 'server_socket') and self.chat_system.server_socket:
            try:
                self.chat_system.server_socket.close()
            except:
                pass

    def test_init(self):
        """Testa inicialização da classe P2PChat"""
        system = P2PChat()
        self.assertIsNotNone(system.my_ip)
        self.assertEqual(len(system.peers), 0)
        self.assertEqual(len(system.connections), 0)
        self.assertEqual(len(system.chat_history), 0)
        self.assertFalse(system.running)

    def test_init_with_bind_ip(self):
        """Testa inicialização com IP específico"""
        bind_ip = "192.168.1.100"
        system = P2PChat(bind_ip=bind_ip)
        self.assertEqual(system.my_ip, bind_ip)
        self.assertEqual(system.bind_ip, bind_ip)

    @patch('p2p_chat_base.socket.socket')
    def test_get_local_ip(self, mock_socket):
        """Testa obtenção do IP local"""
        mock_sock = Mock()
        mock_sock.getsockname.return_value = ("192.168.1.10", 12345)
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        system = P2PChat()
        ip = system._get_local_ip()
        
        self.assertEqual(ip, "192.168.1.10")

    @patch('p2p_chat_base.socket.socket')
    def test_get_local_ip_fallback(self, mock_socket):
        """Testa fallback do IP local em caso de erro"""
        mock_socket.side_effect = Exception("Network error")
        
        system = P2PChat()
        ip = system._get_local_ip()
        
        self.assertEqual(ip, "127.0.0.1")

    def test_recv_exact_success(self):
        """Testa leitura exata de bytes com sucesso"""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [b'abc', b'def', b'ghi']
        
        result = self.chat_system._recv_exact(mock_sock, 9)
        self.assertEqual(result, b'abcdefghi')

    def test_recv_exact_connection_closed(self):
        """Testa leitura exata quando conexão é fechada"""
        mock_sock = Mock()
        mock_sock.recv.side_effect = [b'abc', b'']  # Segunda chamada retorna vazio
        
        with self.assertRaises(ConnectionError):
            self.chat_system._recv_exact(mock_sock, 6)

    def test_serialize_history_empty(self):
        """Testa serialização de histórico vazio"""
        data = self.chat_system._serialize_history()
        self.assertEqual(data, b'')

    def test_serialize_history_with_chats(self):
        """Testa serialização de histórico com chats"""
        chat1 = Chat("Hello", b'\x01' * 16, b'\x02' * 16)
        chat2 = Chat("World", b'\x03' * 16, b'\x04' * 16)
        
        self.chat_system.chat_history = [chat1, chat2]
        data = self.chat_system._serialize_history()
        
        expected = chat1.to_bytes() + chat2.to_bytes()
        self.assertEqual(data, expected)

    def test_deserialize_history_empty(self):
        """Testa deserialização de histórico vazio"""
        history = self.chat_system._deserialize_history(b'')
        self.assertEqual(len(history), 0)

    def test_deserialize_history_with_chats(self):
        """Testa deserialização de histórico com chats"""
        chat1 = Chat("Hello", b'\x01' * 16, b'\x02' * 16)
        chat2 = Chat("World", b'\x03' * 16, b'\x04' * 16)
        
        data = chat1.to_bytes() + chat2.to_bytes()
        history = self.chat_system._deserialize_history(data)
        
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].text, "Hello")
        self.assertEqual(history[1].text, "World")

    def test_validate_history_empty(self):
        """Testa validação de histórico vazio"""
        result = self.chat_system._validate_history([])
        self.assertTrue(result)

    def test_validate_last_chat_empty(self):
        """Testa validação do último chat em histórico vazio"""
        result = self.chat_system._validate_last_chat([])
        self.assertTrue(result)

    def test_calculate_chat_hash_empty(self):
        """Testa cálculo de hash para histórico vazio"""
        hash_result = self.chat_system._calculate_chat_hash([])
        expected = b'\x00' * MD5_SIZE
        self.assertEqual(hash_result, expected)

    def test_calculate_chat_hash_single_chat(self):
        """Testa cálculo de hash para um único chat"""
        verification_code = b'\x01' * 16
        chat = Chat("Test", verification_code, b'\x00' * 16)
        
        hash_result = self.chat_system._calculate_chat_hash([chat])
        
        # Calcula hash esperado
        sequence = struct.pack('B', len("Test")) + b"Test" + verification_code
        expected = hashlib.md5(sequence).digest()
        
        self.assertEqual(hash_result, expected)

    def test_calculate_chat_hash_multiple_chats(self):
        """Testa cálculo de hash para múltiplos chats"""
        chat1 = Chat("First", b'\x01' * 16, b'\x02' * 16)
        chat2 = Chat("Second", b'\x03' * 16, b'\x04' * 16)
        
        hash_result = self.chat_system._calculate_chat_hash([chat1, chat2])
        
        # Calcula hash esperado
        sequence = chat1.to_bytes() + struct.pack('B', len("Second")) + b"Second" + b'\x03' * 16
        expected = hashlib.md5(sequence).digest()
        
        self.assertEqual(hash_result, expected)

    def test_validate_last_chat_invalid_hash_prefix(self):
        """Testa validação de chat com hash inválido (não começa com zeros)"""
        chat = Chat("Test", b'\x01' * 16, b'\x01\x02' + b'\x00' * 14)  # Não começa com dois zeros
        result = self.chat_system._validate_last_chat([chat])
        self.assertFalse(result)

    def test_validate_last_chat_valid(self):
        """Testa validação de chat válido"""
        verification_code = b'\x01' * 16
        
        # Calcula hash válido
        sequence = struct.pack('B', len("Test")) + b"Test" + verification_code
        valid_hash = hashlib.md5(sequence).digest()
        
        # Se o hash não começar com zeros, força para começar (para o teste)
        if valid_hash[:2] != b'\x00\x00':
            valid_hash = b'\x00\x00' + valid_hash[2:]
        
        chat = Chat("Test", verification_code, valid_hash)
        
        # Mock do método _calculate_chat_hash para retornar o hash que criamos
        with patch.object(self.chat_system, '_calculate_chat_hash', return_value=valid_hash):
            result = self.chat_system._validate_last_chat([chat])
            self.assertTrue(result)

    @patch('socket.gethostbyname')
    def test_connect_to_peer_hostname_resolution_error(self, mock_gethostbyname):
        """Testa conexão com erro de resolução de hostname"""
        mock_gethostbyname.side_effect = socket.gaierror("Host not found")
        
        result = self.chat_system._connect_to_peer("invalid.host.com")
        self.assertFalse(result)

    def test_connect_to_peer_self_ip(self):
        """Testa tentativa de conexão com próprio IP"""
        result = self.chat_system._connect_to_peer(self.chat_system.my_ip)
        self.assertFalse(result)

    def test_disconnect_peer(self):
        """Testa desconexão de peer"""
        mock_sock = Mock()
        peer_ip = "192.168.1.100"
        
        # Adiciona peer às estruturas
        self.chat_system.connections[peer_ip] = mock_sock
        self.chat_system.peers.add(peer_ip)
        
        self.chat_system._disconnect_peer(peer_ip)
        
        # Verifica se foi removido
        self.assertNotIn(peer_ip, self.chat_system.connections)
        self.assertNotIn(peer_ip, self.chat_system.peers)
        mock_sock.close.assert_called_once()

    def test_send_peer_request(self):
        """Testa envio de PeerRequest"""
        mock_sock = Mock()
        self.chat_system._send_peer_request(mock_sock)
        
        expected_message = struct.pack('B', MessageType.PEER_REQUEST)
        mock_sock.send.assert_called_once_with(expected_message)

    def test_handle_peer_request(self):
        """Testa tratamento de PeerRequest"""
        mock_sock = Mock()
        peer_ip = "192.168.1.100"
        
        # Adiciona alguns peers
        self.chat_system.peers.add("192.168.1.101")
        self.chat_system.peers.add("192.168.1.102")
        
        self.chat_system._handle_peer_request(peer_ip, mock_sock)
        
        # Verifica se enviou PeerList
        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        
        # Verifica estrutura da mensagem
        self.assertEqual(sent_data[0], MessageType.PEER_LIST)

    def test_handle_archive_request(self):
        """Testa tratamento de ArchiveRequest"""
        mock_sock = Mock()
        peer_ip = "192.168.1.100"
        
        # Adiciona chat ao histórico
        chat = Chat("Test", b'\x01' * 16, b'\x02' * 16)
        self.chat_system.chat_history.append(chat)
        
        self.chat_system._handle_archive_request(peer_ip, mock_sock)
        
        # Verifica se enviou ArchiveResponse
        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        
        # Verifica estrutura da mensagem
        self.assertEqual(sent_data[0], MessageType.ARCHIVE_RESPONSE)

    def test_send_chat_too_long(self):
        """Testa envio de mensagem muito longa"""
        with patch('builtins.print') as mock_print:
            long_message = "a" * 256  # Maior que 255
            self.chat_system._send_chat(long_message)
            mock_print.assert_called_with("Mensagem muito longa (máximo 255 caracteres)")

    def test_send_chat_invalid_characters(self):
        """Testa envio de mensagem com caracteres inválidos"""
        with patch('builtins.print') as mock_print:
            invalid_message = "Hello@World!"  # Contém caracteres especiais
            self.chat_system._send_chat(invalid_message)
            mock_print.assert_called_with("Mensagem deve conter apenas caracteres alfanuméricos e espaços")

    @patch('threading.Thread')
    def test_send_chat_valid(self, mock_thread):
        """Testa envio de mensagem válida"""
        valid_message = "Hello World"
        
        with patch('builtins.print'):
            self.chat_system._send_chat(valid_message)
        
        # Verifica se thread foi criada
        mock_thread.assert_called_once()

    def test_broadcast_history_no_peers(self):
        """Testa broadcast sem peers conectados"""
        with patch('builtins.print') as mock_print:
            self.chat_system._broadcast_history()
            mock_print.assert_any_call("Nenhum peer conectado para enviar histórico")

    def test_broadcast_history_with_peers(self):
        """Testa broadcast com peers conectados"""
        mock_sock1 = Mock()
        mock_sock2 = Mock()
        
        self.chat_system.connections["192.168.1.100"] = mock_sock1
        self.chat_system.connections["192.168.1.101"] = mock_sock2
        
        chat = Chat("Test", b'\x01' * 16, b'\x02' * 16)
        self.chat_system.chat_history.append(chat)
        
        self.chat_system._broadcast_history()
        
        # Verifica se enviou para ambos os peers
        mock_sock1.send.assert_called_once()
        mock_sock2.send.assert_called_once()

    def test_validate_current_history_empty(self):
        """Testa validação do histórico atual vazio"""
        with patch('builtins.print') as mock_print:
            self.chat_system._validate_current_history()
            mock_print.assert_called_with("Histórico vazio - válido")

    def test_show_status(self):
        """Testa exibição do status do sistema"""
        # Adiciona alguns dados
        self.chat_system.peers.add("192.168.1.100")
        self.chat_system.connections["192.168.1.100"] = Mock()
        self.chat_system.chat_history.append(Chat("Test", b'\x01' * 16, b'\x02' * 16))
        
        with patch('builtins.print') as mock_print:
            self.chat_system._show_status()
        
        # Verifica se todas as informações foram exibidas
        calls = [str(call) for call in mock_print.call_args_list]
        status_output = ''.join(calls)
        
        self.assertIn("Status do sistema", status_output)
        self.assertIn("Peers conhecidos: 1", status_output)
        self.assertIn("Conexões ativas: 1", status_output)
        self.assertIn("Mensagens no histórico: 1", status_output)

    def test_show_peers_empty(self):
        """Testa exibição de peers quando não há nenhum"""
        with patch('builtins.print') as mock_print:
            self.chat_system._show_peers()
            mock_print.assert_called_with("\nNenhum peer conectado")

    def test_show_peers_with_data(self):
        """Testa exibição de peers com dados"""
        self.chat_system.peers.add("192.168.1.100")
        self.chat_system.peers.add("192.168.1.101")
        
        with patch('builtins.print') as mock_print:
            self.chat_system._show_peers()
        
        calls = [str(call) for call in mock_print.call_args_list]
        output = ''.join(calls)
        
        self.assertIn("Peers conectados (2)", output)
        self.assertIn("192.168.1.100", output)
        self.assertIn("192.168.1.101", output)

    def test_show_history_empty(self):
        """Testa exibição de histórico vazio"""
        with patch('builtins.print') as mock_print:
            self.chat_system._show_history()
            mock_print.assert_called_with("\nNenhum chat no histórico")

    def test_show_history_with_data(self):
        """Testa exibição de histórico com dados"""
        chat1 = Chat("Hello", b'\x01' * 16, b'\x02' * 16)
        chat2 = Chat("World", b'\x03' * 16, b'\x04' * 16)
        
        self.chat_system.chat_history = [chat1, chat2]
        
        with patch('builtins.print') as mock_print:
            self.chat_system._show_history()
        
        calls = [str(call) for call in mock_print.call_args_list]
        output = ''.join(calls)
        
        self.assertIn("Histórico de chats (2 mensagens)", output)
        self.assertIn("1: Hello", output)
        self.assertIn("2: World", output)

    def test_show_help(self):
        """Testa exibição da ajuda"""
        with patch('builtins.print') as mock_print:
            self.chat_system._show_help()
        
        calls = [str(call) for call in mock_print.call_args_list]
        output = ''.join(calls)
        
        self.assertIn("Comandos disponíveis", output)
        self.assertIn("help", output)
        self.assertIn("peers", output)
        self.assertIn("history", output)
        self.assertIn("connect", output)
        self.assertIn("chat", output)


class TestMessageHandling(unittest.TestCase):
    """Testes para tratamento de mensagens"""

    def setUp(self):
        """Configuração inicial"""
        self.chat_system = P2PChat(bind_ip="127.0.0.1")
        self.chat_system.running = False

    def test_handle_peer_list_basic(self):
        """Testa tratamento básico de PeerList"""
        mock_sock = Mock()
        
        # Simula resposta com 2 peers
        peer_count_data = struct.pack('!I', 2)
        peer1_data = struct.pack('!BBBB', 192, 168, 1, 100)
        peer2_data = struct.pack('!BBBB', 192, 168, 1, 101)
        
        # Mock do _recv_exact para retornar os dados sequencialmente
        mock_sock_recv = Mock(side_effect=[peer_count_data, peer1_data, peer2_data])
        
        with patch.object(self.chat_system, '_recv_exact', mock_sock_recv):
            with patch.object(self.chat_system, '_connect_to_peer') as mock_connect:
                with patch('threading.Thread') as mock_thread:
                    self.chat_system._handle_peer_list("192.168.1.50", mock_sock)
        
        # Verifica se tentou conectar aos peers (via threads)
        self.assertEqual(mock_thread.call_count, 2)

    def test_handle_archive_response_basic(self):
        """Testa tratamento básico de ArchiveResponse"""
        mock_sock = Mock()
        
        # Cria dados de resposta
        chat_count_data = struct.pack('!I', 1)
        text = "Test"
        text_len_data = struct.pack('B', len(text))
        text_data = text.encode('ascii')
        verification_code = b'\x01' * 16
        md5_hash = b'\x00\x00' + b'\x02' * 14  # Hash que começa com dois zeros
        
        # Mock do _recv_exact
        recv_calls = [
            chat_count_data,
            text_len_data,
            text_data,
            verification_code,
            md5_hash
        ]
        
        with patch.object(self.chat_system, '_recv_exact', side_effect=recv_calls):
            with patch.object(self.chat_system, '_validate_history', return_value=True):
                self.chat_system._handle_archive_response("192.168.1.100", mock_sock)
        
        # Verifica se o chat foi adicionado
        self.assertEqual(len(self.chat_system.chat_history), 1)
        self.assertEqual(self.chat_system.chat_history[0].text, "Test")


class TestMining(unittest.TestCase):
    """Testes para mineração de chats"""

    def setUp(self):
        """Configuração inicial"""
        self.chat_system = P2PChat(bind_ip="127.0.0.1")
        self.chat_system.running = False

    @patch('random.randint')
    @patch('hashlib.md5')
    def test_mine_chat_success(self, mock_md5, mock_randint):
        """Testa mineração bem-sucedida de chat"""
        # Mock para gerar código verificador específico
        mock_randint.return_value = 1
        
        # Mock para MD5 retornar hash que começa com zeros
        mock_hash = Mock()
        mock_hash.digest.return_value = b'\x00\x00' + b'\x01' * 14
        mock_md5.return_value = mock_hash
        
        result = self.chat_system._mine_chat("Test")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.text, "Test")
        self.assertEqual(result.verification_code, b'\x01' * 16)

    def test_mine_and_send_chat(self):
        """Testa mineração e envio de chat"""
        # Mock da mineração para retornar imediatamente
        mock_chat = Chat("Test", b'\x01' * 16, b'\x00\x00' + b'\x02' * 14)
        
        with patch.object(self.chat_system, '_mine_chat', return_value=mock_chat):
            with patch.object(self.chat_system, '_broadcast_history') as mock_broadcast:
                self.chat_system._mine_and_send_chat("Test")
        
        # Verifica se foi adicionado ao histórico
        self.assertEqual(len(self.chat_system.chat_history), 1)
        self.assertEqual(self.chat_system.chat_history[0].text, "Test")
        
        # Verifica se fez broadcast
        mock_broadcast.assert_called_once()


class TestRequestHistory(unittest.TestCase):
    """Testes para solicitação de histórico"""

    def setUp(self):
        """Configuração inicial"""
        self.chat_system = P2PChat(bind_ip="127.0.0.1")
        self.chat_system.running = False

    def test_request_history_no_peers(self):
        """Testa solicitação de histórico sem peers"""
        with patch('builtins.print') as mock_print:
            self.chat_system._request_history_from_peers()
            mock_print.assert_called_with("Nenhum peer conectado para solicitar histórico")

    def test_request_history_with_peers(self):
        """Testa solicitação de histórico com peers"""
        mock_sock1 = Mock()
        mock_sock2 = Mock()
        
        self.chat_system.connections["192.168.1.100"] = mock_sock1
        self.chat_system.connections["192.168.1.101"] = mock_sock2
        
        self.chat_system._request_history_from_peers()
        
        # Verifica se enviou ArchiveRequest para ambos
        expected_message = struct.pack('B', MessageType.ARCHIVE_REQUEST)
        mock_sock1.send.assert_called_once_with(expected_message)
        mock_sock2.send.assert_called_once_with(expected_message)

    def test_request_history_with_error(self):
        """Testa solicitação de histórico com erro de envio"""
        mock_sock = Mock()
        mock_sock.send.side_effect = Exception("Connection error")
        
        self.chat_system.connections["192.168.1.100"] = mock_sock
        
        with patch.object(self.chat_system, '_disconnect_peer') as mock_disconnect:
            self.chat_system._request_history_from_peers()
        
        # Verifica se desconectou o peer com erro
        mock_disconnect.assert_called_once_with("192.168.1.100")


if __name__ == '__main__':
    # Configuração para execução dos testes
    unittest.main(verbosity=2)
