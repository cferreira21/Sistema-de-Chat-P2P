#!/usr/bin/env python3
"""
Script para executar todos os testes do sistema P2P Chat
"""

import unittest
import sys
import os
import time
from io import StringIO

def run_all_tests():
    """Executa todos os testes e gera relatório"""
    
    print("=" * 60)
    print("EXECUTANDO TESTES DO SISTEMA P2P CHAT")
    print("=" * 60)
    print()
    
    # Descobre todos os testes
    loader = unittest.TestLoader()
    
    # Carrega testes dos arquivos
    test_files = ['test_p2p_chat', 'test_integration']
    suite = unittest.TestSuite()
    
    for test_file in test_files:
        try:
            tests = loader.loadTestsFromName(test_file)
            suite.addTests(tests)
            print(f"✓ Carregados testes de {test_file}")
        except Exception as e:
            print(f"✗ Erro ao carregar {test_file}: {e}")
    
    print()
    
    # Captura output dos testes
    stream = StringIO()
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=2,
        buffer=True
    )
    
    # Executa os testes
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Mostra resultados
    test_output = stream.getvalue()
    print(test_output)
    
    # Relatório resumido
    print("=" * 60)
    print("RELATÓRIO FINAL")
    print("=" * 60)
    print(f"Testes executados: {result.testsRun}")
    print(f"Sucessos: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Falhas: {len(result.failures)}")
    print(f"Erros: {len(result.errors)}")
    print(f"Tempo total: {end_time - start_time:.2f} segundos")
    print()
    
    # Mostra falhas detalhadas
    if result.failures:
        print("FALHAS:")
        print("-" * 40)
        for test, traceback in result.failures:
            print(f"❌ {test}")
            print(f"   {traceback.splitlines()[-1]}")
        print()
    
    # Mostra erros detalhados
    if result.errors:
        print("ERROS:")
        print("-" * 40)
        for test, traceback in result.errors:
            print(f"💥 {test}")
            print(f"   {traceback.splitlines()[-1]}")
        print()
    
    # Status final
    if result.wasSuccessful():
        print("🎉 TODOS OS TESTES PASSARAM!")
        return 0
    else:
        print("❌ ALGUNS TESTES FALHARAM!")
        return 1

def run_specific_test_class(class_name):
    """Executa apenas uma classe específica de testes"""
    print(f"Executando testes da classe: {class_name}")
    print("-" * 40)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(class_name)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

def run_specific_test_method(test_name):
    """Executa um teste específico"""
    print(f"Executando teste: {test_name}")
    print("-" * 40)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_name)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

def show_help():
    """Mostra ajuda do script"""
    print("Uso: python run_tests.py [opção]")
    print()
    print("Opções:")
    print("  (sem argumentos)    - Executa todos os testes")
    print("  -h, --help         - Mostra esta ajuda")
    print("  --class CLASS      - Executa apenas testes da classe especificada")
    print("  --test TEST        - Executa apenas o teste especificado")
    print()
    print("Exemplos:")
    print("  python run_tests.py")
    print("  python run_tests.py --class test_p2p_chat.TestChat")
    print("  python run_tests.py --test test_p2p_chat.TestChat.test_chat_creation")
    print()
    print("Classes de teste disponíveis:")
    print("  test_p2p_chat.TestChat")
    print("  test_p2p_chat.TestP2PChat")
    print("  test_p2p_chat.TestMessageHandling")
    print("  test_p2p_chat.TestMining")
    print("  test_p2p_chat.TestRequestHistory")
    print("  test_integration.TestP2PChatIntegration")
    print("  test_integration.TestProtocolCompliance")

if __name__ == '__main__':
    # Adiciona diretório atual ao path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    if len(sys.argv) == 1:
        # Executa todos os testes
        exit_code = run_all_tests()
    elif sys.argv[1] in ['-h', '--help']:
        show_help()
        exit_code = 0
    elif sys.argv[1] == '--class' and len(sys.argv) == 3:
        exit_code = run_specific_test_class(sys.argv[2])
    elif sys.argv[1] == '--test' and len(sys.argv) == 3:
        exit_code = run_specific_test_method(sys.argv[2])
    else:
        print("Argumentos inválidos. Use --help para ver as opções.")
        exit_code = 1
    
    sys.exit(exit_code)
