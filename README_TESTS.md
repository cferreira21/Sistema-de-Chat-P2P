# Testes do Sistema P2P Chat

Este diretório contém testes unitários e de integração abrangentes para o sistema P2P Chat.

## Estrutura dos Testes

### 📁 Arquivos de Teste

- **`test_p2p_chat.py`** - Testes unitários principais
- **`test_integration.py`** - Testes de integração e cenários complexos
- **`run_tests.py`** - Script para executar todos os testes
- **`README_TESTS.md`** - Esta documentação

### 🧪 Classes de Teste

#### test_p2p_chat.py

1. **TestChat** - Testa a classe Chat
   - Criação de objetos Chat
   - Serialização para bytes (`to_bytes()`)
   - Deserialização de bytes (`from_bytes()`)
   - Roundtrip de serialização

2. **TestP2PChat** - Testa a classe principal P2PChat
   - Inicialização do sistema
   - Obtenção do IP local
   - Leitura robusta de dados (`_recv_exact()`)
   - Serialização/deserialização do histórico
   - Validação do histórico
   - Cálculo de hashes MD5
   - Conexão/desconexão de peers
   - Broadcast de histórico
   - Interface de usuário (status, peers, histórico)

3. **TestMessageHandling** - Testa tratamento de mensagens
   - Tratamento de PeerList
   - Tratamento de ArchiveResponse
   - Validação de protocolos

4. **TestMining** - Testa mineração de chats
   - Mineração bem-sucedida
   - Envio após mineração
   - Validação de códigos verificadores

5. **TestRequestHistory** - Testa solicitação de histórico
   - Solicitação sem peers
   - Solicitação com múltiplos peers
   - Tratamento de erros

#### test_integration.py

1. **TestP2PChatIntegration** - Testes de cenários complexos
   - Serialização de múltiplos chats
   - Cálculo de hash em cadeia
   - Validação em cadeia
   - Ciclo de vida de peers
   - Conexões simultâneas
   - Históricos grandes
   - Recuperação de erros
   - Segurança de threading

2. **TestProtocolCompliance** - Testes de conformidade
   - Formato de mensagens PeerRequest
   - Formato de mensagens PeerList
   - Formato de mensagens ArchiveResponse
   - Formato de chats
   - Codificação de endereços IP

## 🚀 Como Executar os Testes

### Executar Todos os Testes
```bash
python run_tests.py
```

### Executar Classe Específica
```bash
python run_tests.py --class test_p2p_chat.TestChat
python run_tests.py --class test_integration.TestP2PChatIntegration
```

### Executar Teste Específico
```bash
python run_tests.py --test test_p2p_chat.TestChat.test_chat_creation
python run_tests.py --test test_integration.TestP2PChatIntegration.test_large_history_handling
```

### Obter Ajuda
```bash
python run_tests.py --help
```

### Executar com unittest Diretamente
```bash
# Todos os testes
python -m unittest discover -v

# Arquivo específico
python -m unittest test_p2p_chat -v
python -m unittest test_integration -v

# Classe específica
python -m unittest test_p2p_chat.TestChat -v

# Teste específico
python -m unittest test_p2p_chat.TestChat.test_chat_creation -v
```

## 📊 Cobertura dos Testes

Os testes cobrem as seguintes funcionalidades:

### ✅ Funções Testadas

#### Classe Chat:
- `__init__()`
- `to_bytes()`
- `from_bytes()`

#### Classe P2PChat:
- `__init__()`
- `_get_local_ip()`
- `_recv_exact()`
- `_serialize_history()`
- `_deserialize_history()`
- `_validate_history()`
- `_validate_last_chat()`
- `_calculate_chat_hash()`
- `_connect_to_peer()`
- `_disconnect_peer()`
- `_send_peer_request()`
- `_handle_peer_request()`
- `_handle_peer_list()`
- `_handle_archive_request()`
- `_handle_archive_response()`
- `_request_history_from_peers()`
- `_validate_current_history()`
- `_show_status()`
- `_show_peers()`
- `_show_history()`
- `_show_help()`
- `_send_chat()`
- `_mine_chat()`
- `_mine_and_send_chat()`
- `_broadcast_history()`

### 🧪 Cenários Testados

1. **Serialização/Deserialização**
   - Chats individuais
   - Histórico completo
   - Dados vazios
   - Dados grandes

2. **Validação**
   - Histórico vazio
   - Histórico válido
   - Histórico inválido
   - Validação recursiva
   - Limites de tamanho

3. **Rede e Conexões**
   - Resolução de hostname
   - Conexões bem-sucedidas
   - Falhas de conexão
   - Desconexões
   - Múltiplas conexões simultâneas

4. **Protocolos de Mensagem**
   - PeerRequest
   - PeerList
   - ArchiveRequest
   - ArchiveResponse
   - Tipos desconhecidos

5. **Mineração**
   - Mineração bem-sucedida
   - Códigos verificadores
   - Hashes válidos

6. **Interface de Usuário**
   - Comandos válidos
   - Comandos inválidos
   - Exibição de status
   - Validação de entrada

7. **Threading e Concorrência**
   - Operações thread-safe
   - Locks apropriados
   - Condições de corrida

8. **Tratamento de Erros**
   - Erros de rede
   - Dados corrompidos
   - Conexões perdidas
   - Fallback UTF-8

## 🎯 Exemplos de Uso dos Testes

### Teste de Desenvolvimento
Durante o desenvolvimento, execute testes específicos:
```bash
# Testando apenas serialização
python run_tests.py --class test_p2p_chat.TestChat

# Testando apenas rede
python run_tests.py --test test_p2p_chat.TestP2PChat.test_connect_to_peer_hostname_resolution_error
```

### Teste de Integração
Antes de fazer deploy:
```bash
# Todos os testes
python run_tests.py

# Apenas testes de integração
python run_tests.py --class test_integration.TestP2PChatIntegration
```

### Debug de Problemas
Para debugar problemas específicos:
```bash
# Testes de protocolo
python run_tests.py --class test_integration.TestProtocolCompliance

# Testes de threading
python run_tests.py --test test_integration.TestP2PChatIntegration.test_threading_safety
```

## 📈 Interpretando os Resultados

### ✅ Sucesso
```
Ran 45 tests in 2.341s

OK
🎉 TODOS OS TESTES PASSARAM!
```

### ❌ Falha
```
Ran 45 tests in 2.341s

FAILED (failures=2, errors=1)

FALHAS:
❌ test_p2p_chat.TestChat.test_chat_creation
   AssertionError: 'Hello' != 'Hi'

ERROS:
💥 test_p2p_chat.TestP2PChat.test_connect_to_peer
   ConnectionError: Network unreachable
```

## 🔧 Adicionando Novos Testes

Para adicionar novos testes:

1. **Para funções simples**: Adicione ao `test_p2p_chat.py`
2. **Para cenários complexos**: Adicione ao `test_integration.py`
3. **Siga as convenções**: Use `test_` como prefixo
4. **Use mocks**: Para dependências externas (socket, threading)
5. **Teste casos extremos**: Entradas inválidas, erros de rede, etc.

### Exemplo de Novo Teste
```python
def test_nova_funcionalidade(self):
    """Testa nova funcionalidade"""
    # Arrange
    sistema = P2PChat()
    
    # Act
    resultado = sistema.nova_funcao("parametro")
    
    # Assert
    self.assertEqual(resultado, "esperado")
```

## 🐛 Troubleshooting

### Problemas Comuns

1. **ImportError**: Certifique-se de que o arquivo principal está no mesmo diretório
2. **Socket errors**: Alguns testes podem falhar em ambientes restritivos
3. **Threading issues**: Execute testes em ambiente single-threaded se necessário

### Debugging
```bash
# Execução verbose
python -m unittest test_p2p_chat -v

# Com buffer desabilitado
python -u run_tests.py
```
