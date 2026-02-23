Validação Interna de Usuários (Microsoft 365 / Microsoft Graph)
Autor: Thiago A. Ferreira
Última atualização: 23/02/2026

1) Objetivo
• Validar se um usuário existe no diretório (Entra ID).
• Identificar se a conta está ativa/desativada (accountEnabled).
• Processar listas de e‑mails (CSV) e retornar apenas os inválidos para saneamento de dados / automações internas.

2) Arquitetura (alto nível)
• Cliente: scripts Python (CLI).
* Adaptada para PHP pelo time de Web do Marketing, mas os testes ocorreram em Python.
• API consumida: Microsoft Graph (endpoint /v1.0/users).
• Autenticação: OAuth2 Client Credentials (app-only).
• Permissões: User.Read.All (Application) ou Directory.Read.All (Application), com Admin Consent.
• Execução: WSL (Ubuntu) em notebook corporativo.
Por que “Application permissions”? Rodamos sem usuário logado (serviço/daemon/CLI). Para ler usuários via Graph nesse modo, as permissões são do tipo Application e exigem consentimento do administrador.

3) Pré-requisitos
3.1. Registro do aplicativo (Microsoft Entra ID)
• Entra ID → App registrations → New registration. Name: "ValidadorUsuariosGraph" (sugestão). Accounts in this organizational directory only.
• Certificates & secrets → New client secret. Salvar o Client Secret (valor).
• API permissions → Add a permission → Microsoft Graph → Application → adicionar User.Read.All. Se o tenant restringe "Read other users" ou diretório for mais fechado, adicionar também Directory.Read.All.
• Grant admin consent para a organização.
Notas importantes: Mudanças de permissão só valem para tokens novos (gere outro token ao testar). Em diretórios com política de privacidade, talvez seja necessário Directory.Read.All.

3.2. Variáveis do app
• Tenant (Directory) ID
• Client ID
• Client Secret

4) Scripts criados
4.1. Consulta unitária (interativa) — verifica.py
O que faz: Pergunta o e‑mail (UPN) e consulta GET /v1.0/users/{UPN}?$select=..., exibindo Nome, UPN, Mail e Status (Ativo/Desativado).

4.2. Consulta em lote (CSV) — verifica_lote.py
O que faz: lê um e‑mail por linha (sem cabeçalho), valida no Graph e gera apenas os inválidos (malformados ou 404) em um CSV de saída.
Uso recomendado (um e‑mail por linha): python3 verifica_lote.py --input emails.csv --index 0 --delimiter "," --output invalidos.csv
Opção adicional: --use-filter para tentar $filter quando /users/{UPN} retornar 404.
Observação: Usuário desativado é válido (200 com accountEnabled=false). Inválido = malformado ou 404.

5) Execução no WSL (Ubuntu)
• Opção A: sudo apt update && sudo apt install -y python3-requests
• Opção B (isolado): sudo apt install -y python3-venv; python3 -m venv .venv; source .venv/bin/activate; pip install requests

6) Erros comuns e como resolver (troubleshooting)
• 403 Authorization_RequestDenied: Falta permissão Application ou admin consent. Adicionar User.Read.All (ou Directory.Read.All) e dar Grant admin consent; gerar novo token.
• 401 Unauthorized: Token inválido/expirado; credenciais incorretas. Conferir tenant_id, client_id, client_secret; gerar novo token.
• 404 Not Found (usuário conhecido): mail != userPrincipalName ou usuário excluído/oculto. Usar --use-filter; opcionalmente checar deletedItems.
• 429 Too Many Requests: Throttling do Graph. Reexecutar depois ou implementar retry/backoff.
• CSV marcando inválidos por usar ponto como separador: Forçar --delimiter "," ou usar modo texto simples (um por linha).

7) Segurança e conformidade
• Segredos no código apenas em laboratório. Em produção, use variáveis de ambiente ou secret manager.
• Princípio de menor privilégio: começar com User.Read.All; usar Directory.Read.All apenas se necessário.
• Evitar logar dados sensíveis; sanitizar erros.
• Rotacionar o Client Secret periodicamente.

8) Melhorias futuras
• Uso do Graph $batch para grandes volumes.
• Retry/backoff automático para 429/5xx.
• Checagem de soft-deleted via /directory/deletedItems.
• Empacotamento como API interna (FastAPI/Flask).
• Relatório CSV completo (e-mail, status, motivo).

9) Procedimentos operacionais (SOP)
9.1. Validar um único e‑mail
• Executar: python3 verifica.py
• Informar o e‑mail solicitado
• Registrar o resultado: ATIVO/DESATIVADO/INEXISTENTE
9.2. Processar uma lista (CSV) e criar uma lista de e-mails inválidos (inválidos.csv)
• Preparar arquivo emails.csv (um e‑mail por linha).
• Executar: python3 verifica_lote.py --input emails.csv --index 0 --delimiter "," --output invalidos.csv
• Entregar invalidos.csv ao solicitante.
10) Referências
• Microsoft Graph – Resolver erros de autorização (401/403): verificar tipo de permissão, consent e token novo.
• Microsoft Entra – Conceder admin consent (tenant-wide) para o aplicativo.
