# DCC Internet P2P Blockchain Chat

Sistema de chat distribuído peer-to-peer com verificação por blockchain, implementado em Python conforme especificação do trabalho.

## Funcionalidades Implementadas

### ✅ Parte 1: Identificação de Pares e Rede P2P
- Estabelecimento de conexões P2P na porta 51511
- Mensagens `PeerRequest` e `PeerList` 
- Descoberta automática de peers a cada 5 segundos
- Conexão automática a novos peers descobertos

### ✅ Parte 2: Histórico de Chats
- Mensagens `ArchiveRequest` e `ArchiveResponse`
- Validação recursiva de histórico usando MD5
- Verificação de hash com prefixo de dois bytes zero
- Mineração de código verificador para novos chats

### ✅ Parte 3: Envio de Chats
- Mineração de chats com proof-of-work
- Disseminação automática de novo histórico
- Validação completa antes de aceitar histórico

## Requisitos

- Python 3.6+
- Bibliotecas padrão: `socket`, `threading`, `struct`, `hashlib`, `time`, `random`

## Instalação e Uso

### 1. Executar o Primeiro Peer (Nó Inicial)

```bash
python p2p_chat.py
```

### 2. Conectar Outros Peers

```bash
python p2p_chat.py <IP_DO_PEER_INICIAL>
```

Exemplo:
```bash
python p2p_chat.py 127.0.0.1
```

## Comandos Disponíveis

- `help` - Mostra ajuda
- `peers` - Lista peers conectados
- `history` - Mostra histórico de chats
- `request` - Solicita histórico de todos os peers
- `connect <ip>` - Conecta a um peer específico
- `chat <mensagem>` - Envia uma mensagem (inicia mineração)
- `validate` - Valida o histórico atual
- `status` - Mostra status do sistema
- `quit` - Encerra o programa

## Exemplo de Uso

```bash
# Terminal 1 - Peer inicial
$ python p2p_chat.py
Sistema P2P iniciado no IP 127.0.0.1:51511
Digite 'help' para ver os comandos disponíveis
> status
Status do sistema:
  IP local: 127.0.0.1:51511
  Peers conhecidos: 0
  Conexões ativas: 0
  Chats no histórico: 0

# Terminal 2 - Segundo peer
$ python p2p_chat.py 127.0.0.1
Conectando ao peer inicial: 127.0.0.1
Conectado ao peer 127.0.0.1
Sistema P2P iniciado no IP 127.0.0.1:51511
> peers
Peers conectados (1):
  127.0.0.1

# Terminal 1 - Enviando chat
> chat hello world
Minerando chat: 'hello world'...
Minerando... Tentativas: 10000, Taxa: 15234/s
Chat minerado com sucesso! Tentativas: 23456, Tempo: 1.54s
Chat minerado e adicionado ao histórico: 'hello world'
```

## Testes

### Testes Básicos
```bash
python test_p2p.py test
```

### Criar Histórico de Teste
```bash
python test_p2p.py history
```

### Instruções de Teste Interativo
```bash
python test_p2p.py interactive
```

## Protocolo de Rede

### Mensagens Implementadas

1. **PeerRequest [0x1]** - 1 byte
   - Solicita lista de peers conhecidos

2. **PeerList [0x2]** - 5 + 4×N bytes
   - Retorna lista de N peers (IPs como inteiros de 4 bytes)

3. **ArchiveRequest [0x3]** - 1 byte
   - Solicita histórico de chats

4. **ArchiveResponse [0x4]** - 5 bytes + dados dos chats
   - Retorna histórico completo com C chats

### Formato dos Chats

Cada chat contém:
- 1 byte: tamanho do texto (N)
- N bytes: texto em ASCII
- 16 bytes: código verificador
- 16 bytes: hash MD5

## Algoritmo de Validação

O histórico é válido se:
1. O hash MD5 do último chat começa com dois bytes zero
2. O hash MD5 é calculado corretamente sobre os últimos 20 chats
3. O histórico anterior (recursivo) é válido

## Mineração de Chats

Para adicionar um chat:
1. Gera código verificador aleatório
2. Calcula hash MD5 dos últimos 20 chats + novo chat
3. Verifica se hash começa com 0x0000
4. Repete até encontrar hash válido
5. Adiciona ao histórico e dissemina

## Configuração de Rede

- **Porta fixa**: 51511
- **Descoberta**: A cada 5 segundos
- **Encoding**: ASCII para textos
- **Byte order**: Network byte order para inteiros

## Limitações

- Máximo 255 caracteres por chat
- Apenas caracteres alfanuméricos e espaços
- Um programa por IP (porta única)
- Requer encaminhamento de porta em NAT

## Troubleshooting

### Erro "Address already in use"
```bash
# Linux - adicionar IP adicional
sudo ip addr add 127.0.0.2/8 dev lo
python p2p_chat.py
```

### Problemas de Conexão
- Verificar firewall/NAT
- Confirmar porta 51511 disponível
- Testar conectividade de rede

### Mineração Lenta
- Normal: ~65535 tentativas em média
- Depende da capacidade do processador
- Progresso mostrado a cada 10000 tentativas

## Estrutura do Código

```
p2p_chat.py         # Implementação principal
├── MessageType     # Enum dos tipos de mensagem
├── Chat           # Classe para representar chats
├── P2PChat        # Classe principal do sistema
│   ├── Rede       # Conexões P2P e servidor
│   ├── Descoberta # Loop de descoberta de peers
│   ├── Histórico  # Validação e sincronização
│   ├── Mineração  # Proof-of-work para chats
│   └── Interface  # Comandos do usuário
└── main()         # Função principal
```

## Conformidade com Especificação

✅ Todas as partes implementadas conforme especificação:
- Estrutura de mensagens em network byte order
- Validação recursiva de histórico
- Mineração com prefixo de dois bytes zero
- Threads para múltiplas conexões
- Disseminação automática de histórico
- Descoberta periódica de peers
