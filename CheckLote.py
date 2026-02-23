#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import re
import sys
from typing import Optional

import requests

# =======================
# CONFIG DO APLICATIVO
# =======================
TENANT_ID = "TENANT_ID"
CLIENT_ID = "CLIENTE_ID"
CLIENT_SECRET = "SECRET_ID"
SCOPE = "https://graph.microsoft.com/.default"

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SELECT_FIELDS = "id,userPrincipalName,mail,accountEnabled"

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_email(text: str) -> bool:
    return bool(text and EMAIL_REGEX.match(text))


def get_token() -> str:
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": SCOPE,
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        print(f"[ERRO] Falha ao obter token: {r.status_code} {r.text}", file=sys.stderr)
        sys.exit(1)
    return r.json()["access_token"]


def get_user_by_upn(token: str, upn: str) -> requests.Response:
    url = f"{GRAPH_BASE}/users/{requests.utils.quote(upn, safe='')}?$select={SELECT_FIELDS}"
    return requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)


def find_user_by_mail_or_upn(token: str, email: str) -> requests.Response:
    filt = f"mail eq '{email}' or userPrincipalName eq '{email}'"
    url = f"{GRAPH_BASE}/users?$select={SELECT_FIELDS}&$filter={requests.utils.quote(filt, safe='')}"
    return requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)


def read_emails_from_csv(path: str, column: Optional[str], index: Optional[int], delimiter: str) -> list[str]:
    emails: list[str] = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        sniffer = csv.Sniffer()
        sample = f.read(4096)
        f.seek(0)
        # Se o usuário informou delimiter, usamos; senão tentamos detectar
        if not delimiter:
            try:
                dialect = sniffer.sniff(sample)
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ","  # padrão
        reader = csv.reader(f, delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return emails

        # Se coluna nomeada foi fornecida, trate como cabeçalho
        if column is not None:
            header = rows[0]
            try:
                col_idx = header.index(column)
            except ValueError:
                raise SystemExit(f"[ERRO] Coluna '{column}' não encontrada no cabeçalho: {header}")
            # percorre a partir da 2ª linha
            for row in rows[1:]:
                if col_idx < len(row):
                    emails.append(row[col_idx].strip())
        else:
            # Usa índice numérico (0-based) ou 0 por padrão
            col_idx = index if index is not None else 0
            for row in rows:
                if col_idx < len(row):
                    emails.append(row[col_idx].strip())

    return emails


def write_invalids_to_csv(invalids: list[str], output: str):
    with open(output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["email_invalido"])
        for e in invalids:
            w.writerow([e])


def main():
    parser = argparse.ArgumentParser(
        description="Valida uma lista de e-mails no Microsoft Graph e retorna apenas os inválidos."
    )
    parser.add_argument("--input", required=True, help="Caminho do CSV de entrada.")
    parser.add_argument("--col", help="Nome da coluna que contém os e-mails (usa o cabeçalho).")
    parser.add_argument("--index", type=int, help="Índice da coluna (0-based). Use se não houver cabeçalho.")
    parser.add_argument("--delimiter", default="", help="Delimitador do CSV (padrão: autodetect; fallback ',').")
    parser.add_argument("--output", help="CSV de saída contendo apenas e-mails inválidos (opcional).")
    parser.add_argument("--use-filter", action="store_true",
                        help="Se /users/{UPN} retornar 404, tenta fallback com $filter por mail/UPN.")

    args = parser.parse_args()

    if args.col and args.index is not None:
        print("[AVISO] --col e --index foram informados. Usarei --col e ignorarei --index.", file=sys.stderr)

    try:
        emails = read_emails_from_csv(args.input, args.col, None if args.col else args.index, args.delimiter)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    # Sanitiza lista (remove vazios/duplicados mantendo ordem)
    seen = set()
    clean_emails: list[str] = []
    for e in emails:
        if not e:
            continue
        if e not in seen:
            seen.add(e)
            clean_emails.append(e)

    if not clean_emails:
        print("[INFO] Nenhum e-mail para processar.")
        sys.exit(0)

    token = get_token()

    invalids: list[str] = []
    total = len(clean_emails)
    ok_count = 0

    for i, email in enumerate(clean_emails, start=1):
        # Barra de progresso simples
        print(f"[{i}/{total}] Verificando: {email}")

        # 1) validação sintática
        if not is_email(email):
            invalids.append(email)
            continue

        # 2) Graph: /users/{UPN}
        resp = get_user_by_upn(token, email)

        if resp.status_code == 200:
            ok_count += 1
            continue
        elif resp.status_code == 404:
            if args.use_filter:
                # fallback com $filter
                r2 = find_user_by_mail_or_upn(token, email)
                if r2.status_code == 200:
                    data = r2.json()
                    items = data.get("value", [])
                    if items:
                        ok_count += 1
                        continue
                    else:
                        invalids.append(email)
                        continue
                elif r2.status_code in (401, 403):
                    print(f"[ERRO] Permissão insuficiente no Graph (HTTP {r2.status_code}). "
                          f"Verifique admin consent / User.Read.All / Directory.Read.All.", file=sys.stderr)
                    sys.exit(2)
                elif r2.status_code == 429:
                    print("[ERRO] Throttled (429) pelo Graph no fallback. Tente novamente depois.", file=sys.stderr)
                    sys.exit(3)
                else:
                    print(f"[ERRO] Falha inesperada no fallback: {r2.status_code} {r2.text}", file=sys.stderr)
                    sys.exit(4)
            else:
                invalids.append(email)
                continue
        elif resp.status_code in (401, 403):
            print(f"[ERRO] Permissão insuficiente no Graph (HTTP {resp.status_code}). "
                  f"Verifique admin consent / User.Read.All / Directory.Read.All.", file=sys.stderr)
            sys.exit(2)
        elif resp.status_code == 429:
            print("[ERRO] Throttled (429) pelo Graph. Reexecute mais tarde ou implemente backoff.", file=sys.stderr)
            sys.exit(3)
        else:
            print(f"[ERRO] Erro inesperado do Graph: {resp.status_code} {resp.text}", file=sys.stderr)
            sys.exit(4)

    # Saída
    print("\n===== RESUMO =====")
    print(f"Total processado : {total}")
    print(f"Válidos          : {ok_count}")
    print(f"Inválidos        : {len(invalids)}")

    if invalids:
        print("\nE-mails inválidos:")
        for e in invalids:
            print(f"- {e}")

    if args.output:
        write_invalids_to_csv(invalids, args.output)
        print(f"\n[OK] Arquivo gerado com inválidos: {args.output}")


if __name__ == "__main__":
    # Opcional: permitir configurar via env sem editar o arquivo
    TENANT_ID = os.getenv("TENANT_ID", TENANT_ID)
    CLIENT_ID = os.getenv("CLIENT_ID", CLIENT_ID)
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", CLIENT_SECRET)
    main()
