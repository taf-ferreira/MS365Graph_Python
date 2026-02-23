import requests

# ====== CONFIG ======
tenant_id = "TENANT_ID"
client_id = "CLIENTE_ID"
client_secret = "SECRET_ID"
scope = "https://graph.microsoft.com/.default"

def get_token():
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def validar_usuario(upn: str):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    # Inclui $select para trazer apenas o que importa (inclusive accountEnabled)
    url = f"https://graph.microsoft.com/v1.0/users/{upn}?$select=id,displayName,mail,userPrincipalName,accountEnabled"

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code == 200:
        u = r.json()
        status = "ATIVO ✅" if u.get("accountEnabled") else "DESATIVADO ⛔"
        print("\n🔎 Resultado")
        print("------------")
        print("Nome :", u.get("displayName"))
        print("UPN  :", u.get("userPrincipalName"))
        print("E-mail:", u.get("mail"))
        print("Status:", status)
        print("ID    :", u.get("id"))
    elif r.status_code == 404:
        print("\n❌ Usuário não encontrado (404).")
    else:
        print("\n⚠ Erro inesperado:")
        print("Código:", r.status_code)
        print("Resposta:", r.text)

if __name__ == "__main__":
    print("=== VALIDADOR DE USUÁRIOS M365 ===")
    email = input("Digite o e-mail que deseja verificar: ").strip()
    if "@" not in email:
        print("❌ E-mail inválido.")
    else:
        validar_usuario(email)
