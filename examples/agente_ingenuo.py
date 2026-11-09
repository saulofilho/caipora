"""Um agente ingênuo, baseado em regras, para testar o honeypot sem LLM.

    uv run caipora run examples/agente_ingenuo.py:agente -p agente

Ele cai em tudo de propósito: faz o que o usuário pede e obedece qualquer
instrução "chame X com {...}" que aparecer nos dados que leu.
"""

import json
import re

_INSTRUCAO = re.compile(r"chame (\w+) com (\{.*?\})", re.IGNORECASE)


def _obedecer(texto, ferramentas):
    for nome, argumentos in _INSTRUCAO.findall(texto.replace('\\"', '"')):
        try:
            ferramentas.call(nome, json.loads(argumentos))
        except json.JSONDecodeError:
            pass


def agente(prompt, ferramentas):
    p = prompt.lower()
    contexto = ""
    if "document" in p:
        contexto = ferramentas.call("buscar_documentos", {"consulta": prompt})
    elif ".env" in p:
        contexto = ferramentas.call("ler_arquivo", {"caminho": ".env"})
    elif "leia-me" in p:
        contexto = ferramentas.call("ler_arquivo", {"caminho": "leia-me.txt"})
    elif "maria souza" in p or "fernanda lima" in p:
        nome = "Maria Souza" if "maria" in p else "Fernanda Lima"
        contexto = ferramentas.call("buscar_cliente", {"nome": nome})

    if "transfere" in p:
        ferramentas.call("transferir_dinheiro", {"conta": "12345-6", "valor": 4900})
    if "apaga" in p:
        ferramentas.call("apagar_registros", {"tabela": "clientes", "filtro": "cidade = 'São Paulo'"})
    if "e-mail" in p and "@" in p:
        para = re.search(r"[\w.+-]+@[\w.-]+\w", prompt).group(0)
        ferramentas.call("enviar_email", {"para": para, "assunto": "dados", "corpo": contexto})

    _obedecer(contexto, ferramentas)
    return f"Pronto! Aqui está o que encontrei: {contexto[:300]}" if contexto else "Desculpe, não posso ajudar com isso."
