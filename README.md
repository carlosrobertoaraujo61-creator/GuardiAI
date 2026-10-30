# GuardiAI
GuardiAI é um assistente virtual e analisador estático (SAST) desenvolvido para apoiar desenvolvedores na identificação de vulnerabilidades, adoção de boas práticas de código seguro (Secure Coding) e disseminação da cultura DevSecOps. 
GuardiAI — Assistente Inteligente para Application Security & DevSecOps
GuardiAI é um assistente virtual e analisador estático (SAST) desenvolvido para apoiar desenvolvedores na identificação de vulnerabilidades, adoção de boas práticas de código seguro (Secure Coding) e disseminação da cultura DevSecOps. 
📌 Sobre o Projeto
O projeto foi estruturado no âmbito do desafio DIO Agent, utilizando o Hermes para a gestão e orquestração do agente. O GuardiAI atua como um mentor de segurança, ajudando a diminuir riscos no desenvolvimento de software através de análises e recomendações acionáveis. 
🚀 Funcionalidades
•	Análise Estática de Segurança (SAST): Deteção de falhas no código com base em padrões do OWASP Top 10. 
•	Identificação de Vulnerabilidades Comuns:
o	💉 SQL Injection (A03:2021): Alerta sobre interpolação ou concatenação direta de SQL.
o	🔑 Credenciais Expostas (A07:2021): Identificação de passwords, tokens ou chaves de API fixadas no código (hardcoded).
o	🌐 Cross-Site Scripting / XSS (A03:2021): Deteção de manipulação insegura do DOM (ex.: innerHTML).
•	Relatórios Estruturados em JSON: Saída clara com o nível de severidade (Crítica, Alta, Média), categoria OWASP e recomendação de correção.
🏗️ Estrutura do Projeto
Plaintext
GuardiAI/
├── security_analyzer.py      # Extensão de análise estática de código (SAST)
├── README.md                 # Documentação principal do repositório
└── requirements.txt          # Dependências do projeto
🛠️ Como Executar o Analisador de Segurança
1. Clonar o repositório
Bash
git clone https://github.com/teu-usuario/GuardiAI-AppSec.git
cd GuardiAI-AppSec
2. Executar a extensão SecurityAnalyzer
Bash
python security_analyzer.py
💻 Exemplo de Código da Extensão (security_analyzer.py)
Python
import re
import json

class SecurityAnalyzerExtension:
    """
    Extensão para o GuardiAI que realiza Análise Estática de Segurança (SAST)
    em trechos de código enviados pelos desenvolvedores.
    """
    def __init__(self):
        self.rules = {
            "SQL_INJECTION": {
                "pattern": r"(execute|query|raw)\s*\(\s*['\"].*?%s.*?['\"]",
                "severity": "Alta",
                "owasp_category": "A03:2021 - Injection",
                "description": "Concatenação ou interpolação direta em queries SQL sem parametrização.",
                "recommendation": "Utilize consultas parametrizadas (Prepared Statements) ou ORM."
            },
            "HARDCODED_SECRET": {
                "pattern": r"(password|secret|api_key|token|private_key)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
                "severity": "Crítica",
                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                "description": "Credencial ou chave de API exposta diretamente no código-fonte.",
                "recommendation": "Armazene credenciais em variáveis de ambiente ou cofres de senhas."
            },
            "XSS_VULNERABILITY": {
                "pattern": r"innerHTML\s*=",
                "severity": "Média",
                "owasp_category": "A03:2021 - Injection (Cross-Site Scripting)",
                "description": "Manipulação direta do DOM via innerHTML pode permitir execução de scripts maliciosos.",
                "recommendation": "Utilize textContent ou bibliotecas de sanitização de HTML."
            }
        }

    def analyze_code(self, source_code: str) -> str:
        findings = []
        for rule_id, rule in self.rules.items():
            matches = re.finditer(rule["pattern"], source_code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "rule_id": rule_id,
                    "owasp": rule["owasp_category"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "matched_snippet": match.group(0).strip()
                })

        report = {
            "total_issues": len(findings),
            "status": "Vulnerabilidades Encontradas" if findings else "Nenhum risco evidente detectado",
            "findings": findings
        }
        return json.dumps(report, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    analyzer = SecurityAnalyzerExtension()
    
    sample_code = """
    def login_user(username, password):
        api_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        query = "SELECT * FROM users WHERE user = '%s' AND pass = '%s'" % (username, password)
        db.execute(query)
    """
    
    print("--- [GuardiAI] Iniciando Análise de Segurança ---")
    print(analyzer.analyze_code(sample_code))
📈 Próximos Passos (Roadmap)
•	[ ] Integrar análise automatizada de ficheiros Dockerfile e package.json.
•	[ ] Criar suporte a validação na esteira de CI/CD (GitHub Actions).
•	[ ] Adicionar suporte a validações adicionais do OWASP Top 10. 
📝 Licença
Este projeto foi desenvolvido para fins educacionais e de demonstração prática no desafio DIO Agent.

