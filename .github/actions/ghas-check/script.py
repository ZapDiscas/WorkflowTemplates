import os
import sys
import requests

# Mapeia a severidade para um nível numérico para permitir comparações
SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def fetch_alerts(api_url, headers, min_severity_level, alert_type):
    """Busca os alertas na API e verifica se algum atinge a criticidade mínima."""
    try:
        print(f"Buscando alertas de '{alert_type}' em: {api_url}")
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        alerts = response.json()
        print(f"Encontrados {len(alerts)} alertas abertos.")

        if not alerts:
            return False

        for alert in alerts:
            severity = None
            # A chave de severidade muda entre os tipos de alerta
            if alert_type == "code-scanning":
                severity = alert.get("rule", {}).get("security_severity_level")
            elif alert_type == "dependabot":
                # A API do Dependabot já filtra por severidade, então se recebermos algo, é um alerta.
                # No entanto, vamos verificar para garantir.
                severity = alert.get("security_vulnerability", {}).get("severity")

            # Se a API do Secret Scanning retornar algo, é uma falha.
            elif alert_type == "secret-scanning":
                 print(f"::error::Alerta de Secret Scanning encontrado! URL: {alert.get('html_url')}")
                 return True


            if not severity:
                continue

            alert_level = SEVERITY_LEVELS.get(severity.lower(), 0)

            if alert_level >= min_severity_level:
                print(f"::error::Alerta crítico de '{alert_type}' encontrado! Severidade '{severity}'. URL: {alert.get('html_url')}")
                return True # Encontrou um alerta crítico

    except requests.exceptions.RequestException as e:
        print(f"::error::Falha ao buscar alertas em {api_url}. Erro: {e}")
        return True # Trata erro de API como falha de segurança

    return False # Nenhum alerta crítico encontrado

def main():
    token = os.environ["INPUT_TOKEN"]
    # ✨ NOVO: Pega o repositório e a branch alvo dos inputs!
    target_repo = os.environ["INPUT_TARGET_REPO"]
    target_branch = os.environ["INPUT_TARGET_BRANCH"]

    dependabot_severity = os.environ["INPUT_DEPENDABOT_SEVERITY"]
    codeql_severity = os.environ["INPUT_CODEQL_SEVERITY"]

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}

    min_dependabot_level = SEVERITY_LEVELS.get(dependabot_severity.lower(), 4)
    min_codeql_level = SEVERITY_LEVELS.get(codeql_severity.lower(), 4)

    # URLs da API agora são construídas com os alvos explícitos
    urls_to_check = {
        f"https://api.github.com/repos/{target_repo}/dependabot/alerts?state=open&severity={dependabot_severity}": (min_dependabot_level, "dependabot"),
        f"https://api.github.com/repos/{target_repo}/code-scanning/alerts?state=open&ref=refs/heads/{target_branch}": (min_codeql_level, "code-scanning"),
        f"https://api.github.com/repos/{target_repo}/secret-scanning/alerts?state=open": (4, "secret-scanning") # Qualquer segredo é crítico
    }

    has_critical_alerts = False
    for url, (level, alert_type) in urls_to_check.items():
        if fetch_alerts(url, headers, level, alert_type):
            has_critical_alerts = True

    if has_critical_alerts:
        print("\n❌ Falha na verificação de segurança. Pipeline encerrada.")
        sys.exit(1)
    else:
        print("\n✅ Verificação de segurança concluída. Nenhum alerta crítico encontrado.")
        sys.exit(0)

if __name__ == "__main__":
    main()