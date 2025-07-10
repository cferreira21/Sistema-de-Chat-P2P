# Relatório de Implementação - Sistema de Chat P2P

## 1. Visão Geral da Implementação

Este documento descreve a implementação de um sistema de chat peer-to-peer (P2P) em Python que utiliza um protocolo de comunicação personalizado baseado em TCP/IP. O sistema implementa um mecanismo de consenso distribuído através de mineração de mensagens com validação por hash MD5.

## 2. Arquitetura do Sistema

### 2.1 Estrutura Principal

O sistema é implementado através da classe `P2PChat` que gerencia:
- Conexões de rede com outros peers
- Histórico de mensagens compartilhado
- Processo de mineração de mensagens
- Descoberta automática de peers
- Validação de integridade do histórico

### 2.2 Componentes Principais

#### MessageType (Enum)
Define os tipos de mensagens do protocolo:
- `PEER_REQUEST (0x1)`: Solicitação de lista de peers
- `PEER_LIST (0x2)`: Resposta com lista de peers conhecidos
- `ARCHIVE_REQUEST (0x3)`: Solicitação de histórico de mensagens
- `ARCHIVE_RESPONSE (0x4)`: Resposta com histórico completo

#### Chat (Dataclass)
Representa uma mensagem no histórico com:
- `text`: Conteúdo da mensagem (máximo 255 caracteres ASCII)
- `verification_code`: Código de 16 bytes para mineração
- `md5_hash`: Hash MD5 de 16 bytes para validação

## 3. Mecanismos de Rede

### 3.1 Codificação de Mensagens

O sistema utiliza codificação binária estruturada com o módulo `struct` do Python:

#### Formato PeerRequest
```
[1 byte] - Tipo da mensagem (0x1)
```

#### Formato PeerList
```
[1 byte]  - Tipo da mensagem (0x2)
[4 bytes] - Número de peers (big-endian)
[4 bytes] - IP do peer 1 (4 bytes, um por octeto)
[4 bytes] - IP do peer 2
...
```

#### Formato ArchiveRequest
```
[1 byte] - Tipo da mensagem (0x3)
```

#### Formato ArchiveResponse
```
[1 byte]  - Tipo da mensagem (0x4)
[4 bytes] - Número de chats (big-endian)
[Dados dos chats serialized]
```

#### Formato de Chat Serializado
```
[1 byte]   - Tamanho do texto
[N bytes]  - Texto da mensagem (ASCII)
[16 bytes] - Código de verificação
[16 bytes] - Hash MD5
```

### 3.2 Recebimento de Mensagens

O recebimento é implementado através de:

1. **Socket TCP**: Utiliza `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`
2. **Threads dedicadas**: Cada peer conectado tem uma thread para processar mensagens
3. **Leitura estruturada**: Função `_recv_exact()` garante leitura completa dos dados
4. **Timeout de conexão**: 30 segundos para evitar bloqueios indefinidos

```python
def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
    """Lê exatamente size bytes do socket"""
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Conexão fechada durante leitura")
        data += chunk
    return data
```

### 3.3 Envio de Mensagens

O envio utiliza:

1. **Conexões persistentes**: Mantém conexões TCP abertas com peers
2. **Thread safety**: Locks para acesso concorrente às estruturas de dados
3. **Broadcast**: Envia atualizações para todos os peers conectados
4. **Tratamento de erros**: Desconecta peers em caso de falha

## 4. Descoberta de Peers

### 4.1 Conexão Inicial
- Aceita um peer inicial como parâmetro de linha de comando
- Conecta automaticamente ao peer inicial se fornecido

### 4.2 Descoberta Automática
- Loop de descoberta executa a cada 5 segundos (`PEER_REQUEST_INTERVAL`)
- Envia `PeerRequest` para todos os peers conectados
- Recebe `PeerList` com novos peers
- Conecta automaticamente a novos peers descobertos

### 4.3 Resolução de Hostnames
- Utiliza `socket.gethostbyname()` para resolver hostnames para IPs
- Previne auto-conexão verificando IP local

## 5. Biblioteca para Hash MD5

### 5.1 Biblioteca Utilizada
O sistema utiliza a biblioteca padrão **`hashlib`** do Python para cálculo do hash MD5:

```python
import hashlib

def _calculate_chat_hash(self, history: List[Chat]) -> bytes:
    """Calcula o hash MD5 para validação do último chat"""
    # ... preparação da sequência ...
    return hashlib.md5(sequence).digest()
```

### 5.2 Vantagens da hashlib
- Biblioteca padrão do Python (não requer instalação adicional)
- Implementação otimizada em C
- Suporte a múltiplos algoritmos de hash
- Interface simples e consistente

## 6. Processo de Mineração

### 6.1 Algoritmo de Mineração

O processo de mineração implementa um sistema de "Proof of Work" simplificado:

```python
def _mine_chat(self, message: str) -> Optional[Chat]:
    """Minera um chat encontrando um código verificador válido"""
    while True:
        # Gera código de verificação aleatório
        verification_code = bytes([random.randint(0, 255) for _ in range(16)])
        temp_chat = Chat(message, verification_code, b'\x00' * 16)
        
        # Calcula hash com histórico atual + nova mensagem
        with self.history_lock:
            temp_history = self.chat_history + [temp_chat]
        
        calculated_hash = self._calculate_chat_hash(temp_history)
        
        # Verifica se hash começa com dois bytes zero
        if calculated_hash[:2] == b'\x00' * 2:
            final_chat = Chat(message, verification_code, calculated_hash)
            return final_chat
```

### 6.2 Critério de Validação

Uma mensagem é considerada válida quando:
- O hash MD5 calculado começa com dois bytes zero (`\x00\x00`)
- Isso representa uma dificuldade de 1 em 65.536 (2^16)

### 6.3 Cálculo do Hash

O hash é calculado sobre:
1. **Últimos 20 chats** (ou todos se menos de 20)
2. **Dados serializados** de cada chat (exceto o hash da última mensagem)
3. **Sequência binária** construída concatenando todos os dados

```python
def _calculate_chat_hash(self, history: List[Chat]) -> bytes:
    chats_to_hash = history[-20:]  # Últimos 20 chats
    sequence = b''
    
    for i, chat in enumerate(chats_to_hash):
        if i == len(chats_to_hash) - 1:
            # Última mensagem: exclui o hash MD5
            sequence += struct.pack('B', len(chat.text))
            sequence += chat.text.encode('ascii')
            sequence += chat.verification_code
        else:
            # Outras mensagens: inclui tudo
            sequence += chat.to_bytes()
    
    return hashlib.md5(sequence).digest()
```

## 7. Validação do Histórico

### 7.1 Validação Recursiva

O sistema implementa validação recursiva do histórico:

```python
def _validate_history(self, history: List[Chat]) -> bool:
    """Valida um histórico de chats recursivamente"""
    if not history:
        return True
    
    # Valida histórico sem última mensagem primeiro
    if len(history) > 1:
        if not self._validate_history(history[:-1]):
            return False
    
    # Valida a última mensagem
    return self._validate_last_chat(history)
```

### 7.2 Critérios de Validação

1. **Hash válido**: Hash MD5 deve começar com `\x00\x00`
2. **Integridade**: Hash calculado deve coincidir com o armazenado
3. **Consistência**: Todo o histórico deve ser válido recursivamente

## 8. Thread Safety

O sistema implementa controle de concorrência através de locks:

- `peers_lock`: Protege lista de peers conhecidos
- `connections_lock`: Protege dicionário de conexões ativas
- `history_lock`: Protege histórico de mensagens

## 9. Instruções para Execução

### 9.1 Requisitos

- **Python 3.6+** (utiliza f-strings e type hints)
- **Bibliotecas padrão**: socket, threading, struct, hashlib, time, random, sys
- **Sistema operacional**: Linux, macOS, Windows
- **Rede**: Acesso TCP na porta 51511

### 9.2 Execução Básica

#### Primeiro peer (servidor inicial):
```bash
python3 p2p_chat_base.py
```

#### Peer adicional conectando ao primeiro:
```bash
python3 p2p_chat_base.py <IP_DO_PRIMEIRO_PEER>
```

#### Especificando IP de bind:
```bash
python3 p2p_chat_base.py <IP_PEER_INICIAL> <IP_LOCAL_BIND>
```

### 9.3 Exemplos de Uso

#### Cenário 1: Dois computadores na mesma rede
```bash
# Computador 1 (IP: 192.168.1.100)
python3 p2p_chat_base.py

# Computador 2 (IP: 192.168.1.101)
python3 p2p_chat_base.py 192.168.1.100
```

#### Cenário 2: Testando localmente
```bash
# Terminal 1
python3 p2p_chat_base.py

# Terminal 2
python3 p2p_chat_base.py 127.0.0.1
```

#### Cenário 3: Múltiplos peers
```bash
# Peer 1
python3 p2p_chat_base.py

# Peer 2
python3 p2p_chat_base.py <IP_PEER_1>

# Peer 3
python3 p2p_chat_base.py <IP_PEER_2>
# Peer 3 descobrirá automaticamente Peer 1 através de Peer 2
```

### 9.4 Comandos Disponíveis

Após iniciar o programa, os seguintes comandos estão disponíveis:

- `help` - Mostra lista de comandos
- `peers` - Lista peers conectados
- `hist` - Mostra histórico de mensagens
- `req` - Solicita histórico de todos os peers
- `connect <ip>` - Conecta manualmente a um peer
- `chat <mensagem>` - Envia uma nova mensagem (inicia mineração)
- `val` - Valida o histórico atual
- `status` - Mostra status detalhado do sistema
- `debug` - Ativa/desativa modo debug

### 9.5 Exemplo de Sessão

```bash
$ python3 p2p_chat_base.py
Sistema P2P iniciado no IP 192.168.1.100:51511
Digite 'help' para ver os comandos disponíveis
> status
Status do sistema:
  Meu IP: 192.168.1.100:51511
  Peers conhecidos: 0
  Conexões ativas: 0
  Mensagens no histórico: 0
  Sistema rodando: Sim
  Debug mode: Desativado

> chat Hello World
Minerando chat: 'Hello World'...
Chat minerado e adicionado ao histórico: 'Hello World'
Nenhum peer conectado para enviar histórico

> hist
Histórico de chats (1 mensagens):
  1: Hello World
```

### 9.6 Solução de Problemas

#### Erro de porta ocupada:
```bash
# Verificar se porta 51511 está em uso
netstat -tulpn | grep 51511

# Matar processo se necessário
sudo kill -9 <PID>
```

#### Problemas de firewall:
```bash
# Ubuntu/Debian
sudo ufw allow 51511

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=51511/tcp
sudo firewall-cmd --reload
```

#### Teste de conectividade:
```bash
# Testar se peer está escutando
telnet <IP_PEER> 51511
```

### 9.7 Considerações de Rede

- **Porta padrão**: 51511 (definida na constante `PORT`)
- **Protocolo**: TCP/IP
- **Timeout de conexão**: 5 segundos para novas conexões
- **Timeout de mensagens**: 30 segundos para leitura
- **Descoberta automática**: A cada 5 segundos
- **Binding**: Por padrão, escuta em todas as interfaces (0.0.0.0)

## 10. Limitações e Considerações

### 10.1 Limitações Técnicas

- **Tamanho de mensagem**: Máximo 255 caracteres ASCII
- **Caracteres permitidos**: Apenas alfanuméricos e espaços
- **Escalabilidade**: Adequado para redes pequenas (< 50 peers)
- **Persistência**: Histórico não é salvo em disco

### 10.2 Considerações de Segurança

- **Sem autenticação**: Qualquer peer pode se conectar
- **Sem criptografia**: Mensagens trafegam em texto claro
- **Validação básica**: Confia na validação por hash MD5

### 10.3 Melhorias Futuras

- Implementar persistência em disco
- Adicionar criptografia TLS
- Implementar autenticação de peers
- Otimizar algoritmo de consenso
- Adicionar interface gráfica

## 11. Conclusão

Este sistema implementa com sucesso um protocolo P2P funcional com características de blockchain, incluindo mineração, validação distribuída e sincronização automática. A implementação demonstra conceitos fundamentais de sistemas distribuídos e pode servir como base para aplicações mais complexas.

A escolha de bibliotecas padrão do Python garante portabilidade e facilita a instalação, enquanto o design modular permite extensões futuras. O sistema de mineração, embora simplificado, ilustra efetivamente os princípios de proof-of-work utilizados em criptomoedas.
