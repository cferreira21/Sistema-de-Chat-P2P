#!/usr/bin/env python3
"""
Script de teste para o sistema P2P Chat
"""

import subprocess
import time
import threading
import sys
import os

def run_peer(peer_id, initial_peer=None):
    """Executa um peer do sistema"""
    print(f"Iniciando peer {peer_id}...")
    
    # Prepara comando
    cmd = [sys.executable, "p2p_chat.py"]
    if initial_peer:
        cmd.append(initial_peer)
    
    # Executa o peer
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, 
                                 text=True)
        return process
    except Exception as e:
        print(f"Erro ao iniciar peer {peer_id}: {e}")
        return None

def test_basic_functionality():
    """Teste básico de funcionalidade"""
    print("=== Teste Básico de Funcionalidade ===")
    
    # Teste 1: Validação de histórico vazio
    print("\n1. Testando validação de histórico vazio...")
    from p2p_chat import P2PChat
    
    chat_system = P2PChat()
    assert chat_system._validate_history([]) == True
    print("✓ Histórico vazio é válido")
    
    # Teste 2: Serialização e deserialização
    print("\n2. Testando serialização/deserialização...")
    from p2p_chat import Chat
    import hashlib
    
    # Cria um chat de teste
    message = "teste"
    verification_code = b'\x01' * 16
    md5_hash = hashlib.md5(b"test").digest()
    
    chat = Chat(message, verification_code, md5_hash)
    
    # Serializa
    serialized = chat.to_bytes()
    
    # Deserializa
    deserialized_chat, _ = Chat.from_bytes(serialized, 0)
    
    assert deserialized_chat.text == chat.text
    assert deserialized_chat.verification_code == chat.verification_code
    assert deserialized_chat.md5_hash == chat.md5_hash
    print("✓ Serialização/deserialização funcionando")
    
    # Teste 3: Estrutura de mensagens
    print("\n3. Testando estrutura de mensagens...")
    import struct
    from p2p_chat import MessageType
    
    # Teste PeerRequest
    peer_request = struct.pack('B', MessageType.PEER_REQUEST)
    assert len(peer_request) == 1
    assert struct.unpack('B', peer_request)[0] == MessageType.PEER_REQUEST
    print("✓ Estrutura de mensagens correta")
    
    print("\n✅ Todos os testes básicos passaram!")

def interactive_test():
    """Teste interativo para múltiplos peers"""
    print("=== Teste Interativo ===")
    print("Este teste requer múltiplos terminais.")
    print("Instruções:")
    print("1. Execute este script em um terminal como peer inicial")
    print("2. Em outros terminais, execute: python p2p_chat.py 127.0.0.1")
    print("3. Use os comandos do sistema para testar")
    print("\nComandos úteis para teste:")
    print("- peers: ver peers conectados")
    print("- history: ver histórico de chats")
    print("- chat <mensagem>: enviar chat")
    print("- request: solicitar histórico")
    print("- validate: validar histórico")
    print("- status: ver status do sistema")

def create_test_history():
    """Cria um histórico de teste para demonstração"""
    print("\n=== Criando Histórico de Teste ===")
    
    from p2p_chat import Chat, P2PChat
    import hashlib
    import struct
    
    # Cria sistema para usar funções de hash
    chat_system = P2PChat()
    
    # Mensagens de teste
    messages = [
        "primeiro chat",
        "segundo chat",
        "terceiro chat teste",
        "quarto chat exemplo",
        "quinto chat final"
    ]
    
    history = []
    
    for i, message in enumerate(messages):
        print(f"Criando chat {i+1}: '{message}'")
        
        # Para simplificar, vamos usar códigos verificadores pré-definidos
        # Na prática, estes seriam minerados
        verification_code = bytes([i+1] * 16)
        
        # Cria chat temporário
        temp_chat = Chat(message, verification_code, b'\x00' * 16)
        temp_history = history + [temp_chat]
        
        # Calcula hash real
        calculated_hash = chat_system._calculate_chat_hash(temp_history)
        
        # Cria chat final
        final_chat = Chat(message, verification_code, calculated_hash)
        history.append(final_chat)
        
        print(f"  Hash: {calculated_hash.hex()[:8]}...")
        print(f"  Válido: {chat_system._validate_history(history)}")
    
    print(f"\nHistórico criado com {len(history)} chats")
    return history

def main():
    """Função principal de teste"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            # Executa testes básicos
            test_basic_functionality()
        elif sys.argv[1] == "interactive":
            # Teste interativo
            interactive_test()
        elif sys.argv[1] == "history":
            # Cria histórico de teste
            create_test_history()
        else:
            print("Opções: test, interactive, history")
    else:
        print("Uso: python test_p2p.py [test|interactive|history]")
        print("\nOpções:")
        print("  test        - Executa testes básicos")
        print("  interactive - Instruções para teste interativo")
        print("  history     - Cria e valida histórico de teste")

if __name__ == "__main__":
    main()
