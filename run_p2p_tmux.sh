#!/bin/bash

# Script para executar múltiplos peers P2P Chat usando tmux

# Configurações
SESSION_NAME="p2p_chat_test"
NUM_PEERS=3
INITIAL_PEER_IP="127.0.0.1"

# Cores para os terminais
COLORS=("bg=red" "bg=green" "bg=blue" "bg=yellow" "bg=magenta" "bg=cyan")

# Função para limpar sessão existente
cleanup_session() {
    if tmux has-session -t $SESSION_NAME 2>/dev/null; then
        echo "Encerrando sessão existente..."
        tmux kill-session -t $SESSION_NAME
    fi
}

# Função para criar sessão tmux
create_session() {
    echo "Criando sessão tmux: $SESSION_NAME"
    tmux new-session -d -s $SESSION_NAME -x 120 -y 40
    
    # Configurar primeira janela (peer inicial)
    tmux rename-window -t $SESSION_NAME:0 "Peer-1-Initial"
    tmux send-keys -t $SESSION_NAME:0 "echo 'Iniciando Peer 1 (Inicial)...'" C-m
    tmux send-keys -t $SESSION_NAME:0 "sleep 2" C-m
    tmux send-keys -t $SESSION_NAME:0 "python3 p2p_chat_base.py" C-m
    
    # Criar janelas para outros peers
    for i in $(seq 2 $NUM_PEERS); do
        tmux new-window -t $SESSION_NAME -n "Peer-$i"
        tmux send-keys -t $SESSION_NAME:$((i-1)) "echo 'Aguardando peer inicial... (5s)'" C-m
        tmux send-keys -t $SESSION_NAME:$((i-1)) "sleep 5" C-m
        tmux send-keys -t $SESSION_NAME:$((i-1)) "echo 'Conectando ao peer inicial...'" C-m
        tmux send-keys -t $SESSION_NAME:$((i-1)) "python3 p2p_chat_base.py $INITIAL_PEER_IP" C-m
    done
    
    # Criar janela de controle
    tmux new-window -t $SESSION_NAME -n "Control"
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo 'Painel de Controle - P2P Chat Test'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo 'Comandos úteis:'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo '  - Ctrl+B, números (0-$((NUM_PEERS-1))) para alternar entre peers'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo '  - Ctrl+B, d para destacar da sessão'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo '  - tmux attach -t $SESSION_NAME para reconectar'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo '  - ./run_p2p_tmux.sh stop para encerrar'" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo ''" C-m
    tmux send-keys -t $SESSION_NAME:$NUM_PEERS "echo 'Monitorando peers...'" C-m
    
    # Voltar para primeira janela
    tmux select-window -t $SESSION_NAME:0
}

# Função para conectar à sessão
attach_session() {
    echo "Conectando à sessão $SESSION_NAME..."
    echo "Use Ctrl+B seguido de números (0-$((NUM_PEERS-1))) para alternar entre peers"
    echo "Use Ctrl+B, d para destacar da sessão"
    tmux attach-session -t $SESSION_NAME
}

# Função para mostrar status
show_status() {
    if tmux has-session -t $SESSION_NAME 2>/dev/null; then
        echo "Sessão $SESSION_NAME está ativa"
        echo "Janelas:"
        tmux list-windows -t $SESSION_NAME
    else
        echo "Sessão $SESSION_NAME não está ativa"
    fi
}

# Função para executar comando em todos os peers
run_command_all() {
    local command="$1"
    echo "Executando '$command' em todos os peers..."
    
    for i in $(seq 0 $((NUM_PEERS-1))); do
        tmux send-keys -t $SESSION_NAME:$i "$command" C-m
    done
}

# Função para executar testes automáticos
run_automated_tests() {
    echo "Executando testes automáticos..."
    
    # Aguardar inicialização
    sleep 8
    
    # Executar comandos de teste
    echo "Testando comando 'peers' em todos os peers..."
    run_command_all "peers"
    
    sleep 3
    
    echo "Enviando mensagem de teste do Peer 1..."
    tmux send-keys -t $SESSION_NAME:0 "chat Mensagem de teste do Peer 1" C-m
    
    sleep 2
    
    echo "Enviando mensagem de teste do Peer 2..."
    tmux send-keys -t $SESSION_NAME:1 "chat Mensagem de teste do Peer 2" C-m
    
    sleep 2
    
    echo "Verificando histórico em todos os peers..."
    run_command_all "history"
    
    sleep 3
    
    echo "Validando histórico em todos os peers..."
    run_command_all "validate"
}

# Função principal
main() {
    case "${1:-start}" in
        "start")
            cleanup_session
            create_session
            attach_session
            ;;
        "stop")
            cleanup_session
            echo "Sessão encerrada"
            ;;
        "attach")
            attach_session
            ;;
        "status")
            show_status
            ;;
        "test")
            cleanup_session
            create_session
            echo "Aguardando inicialização dos peers..."
            run_automated_tests
            attach_session
            ;;
        "command")
            if [ -z "$2" ]; then
                echo "Uso: $0 command <comando>"
                exit 1
            fi
            run_command_all "$2"
            ;;
        "help")
            echo "Uso: $0 [start|stop|attach|status|test|command|help]"
            echo ""
            echo "Comandos:"
            echo "  start   - Inicia nova sessão com $NUM_PEERS peers"
            echo "  stop    - Encerra sessão existente"
            echo "  attach  - Conecta à sessão existente"
            echo "  status  - Mostra status da sessão"
            echo "  test    - Inicia sessão e executa testes automáticos"
            echo "  command - Executa comando em todos os peers"
            echo "  help    - Mostra esta ajuda"
            echo ""
            echo "Navegação no tmux:"
            echo "  Ctrl+B, 0-$((NUM_PEERS-1)) - Alternar entre peers"
            echo "  Ctrl+B, $NUM_PEERS - Ir para painel de controle"
            echo "  Ctrl+B, d - Destacar da sessão"
            echo "  Ctrl+B, & - Encerrar janela atual"
            ;;
        *)
            echo "Comando inválido. Use '$0 help' para ver opções."
            exit 1
            ;;
    esac
}

# Verificar se tmux está instalado
if ! command -v tmux &> /dev/null; then
    echo "tmux não está instalado. Instalando..."
    sudo apt update && sudo apt install -y tmux
fi

# Verificar se o arquivo p2p_chat_base.py existe
if [ ! -f "p2p_chat_base.py" ]; then
    echo "Erro: p2p_chat_base.py não encontrado no diretório atual"
    exit 1
fi

# Executar função principal
main "$@"