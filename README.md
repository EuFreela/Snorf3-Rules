# Instalação e Configuração do Snort 3 no [ParrotOS](https://parrotsec.org/)

![snort3](https://blog.talosintelligence.com/content/images/2023/09/Snort-inspectors.jpg)
Este guia cobre os passos necessários para instalar e configurar o **Snort 3**, uma poderosa ferramenta de detecção e prevenção de intrusões (IDS/IPS) no Linux.
Neste github esta uma lista de rules que poderá utilizar nas suas configurações.

## Índice
1. [Pré-requisitos](#pré-requisitos)
2. [Instalando Dependências](#instalando-dependências)
3. [Instalando o DAQ](#instalando-o-daq)
4. [Baixando e Instalando o Snort 3](#baixando-e-instalando-o-snort-3)
5. [Configurando o Snort 3](#configurando-o-snort-3)
6. [Criando Regras Personalizadas](#criando-regras-personalizadas)
7. [Executando o Snort e Verificando Logs](#executando-o-snort-e-verificando-logs)
8. [Conclusão](#conclusão)

## Pré-requisitos
Certifique-se de que seu sistema Linux está atualizado:
```bash
sudo apt update && sudo apt upgrade -y
```

## Instalando Dependências

O Snort 3 requer várias bibliotecas e ferramentas para compilação. Instale as dependências com o comando:

```bash
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdnet-dev zlib1g-dev \
cmake libluajit-5.1-dev openssl libssl-dev pkg-config libhwloc-dev liblzma-dev
```

> **Nota**: Se `libdnet-dev` não estiver disponível, instale `libdumbnet-dev`:
> ```bash
> sudo apt install libdumbnet-dev
> ```

## Instalando o DAQ

O **DAQ (Data Acquisition library)** é necessário para que o Snort capture pacotes de rede. Baixe, extraia e instale o DAQ:

```bash
wget https://www.snort.org/downloads/snort/daq-3.0.0.tar.gz
tar -xzvf daq-3.0.0.tar.gz
cd daq-3.0.0
./configure
make
sudo make install
cd ..
```

## Baixando e Instalando o Snort 3

Baixe o Snort 3 diretamente do GitHub:

```bash
git clone https://github.com/snort3/snort3.git
cd snort3
```

Crie um diretório de build e configure o ambiente com `cmake`:

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

Atualize o cache das bibliotecas compartilhadas para garantir que o sistema reconheça o Snort:

```bash
sudo ldconfig
```

Verifique se o Snort foi instalado corretamente:

```bash
snort -V
```

## Configurando o Snort 3

Após a instalação, crie diretórios para armazenar regras e logs:

```bash
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort
sudo touch /etc/snort/rules/local.rules
sudo touch /etc/snort/snort.lua
```

### Configurando o Arquivo `snort.lua`

O arquivo `snort.lua` é o principal arquivo de configuração do Snort 3. Configure-o para carregar as regras e variáveis de rede:

```lua
ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    include = '/etc/snort/rules/local.rules',
}
```

## Criando Regras Personalizadas

Para adicionar regras ao Snort, edite o arquivo `local.rules`:

```bash
sudo nano /etc/snort/rules/local.rules
```

Exemplo de regras:

```plaintext
alert tcp any any -> any any (msg:"Possible Shell Access"; content:"/bin/sh"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"Suspicious File Access - PDF"; content:"%PDF-"; sid:1000002; rev:1;)
alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; sid:1000003; rev:1;)
```

### Automatizando a Criação de Regras com Script

Crie um script para adicionar mais regras automaticamente:

```bash
#!/bin/bash

RULE_DIR="/etc/snort/rules/"
mkdir -p "$RULE_DIR"

declare -A RULES=(
    ["snort3-content-replace.rules"]='alert tcp any any -> any any (msg:"Content Replace - Detected"; content:"replace-content"; sid:2000002; rev:1;)'
    ["snort3-file-flash.rules"]='alert tcp any any -> any any (msg:"File Transfer - Flash File Detected"; content:".swf"; sid:2000003; rev:1;)'
)

for file in "${!RULES[@]}"; do
    echo "${RULES[$file]}" > "$RULE_DIR/$file"
done

echo "Arquivos de regras criados em $RULE_DIR."
```

Execute o script:

```bash
chmod +x criar_regras_snort.sh
./criar_regras_snort.sh
```

Atualize o `snort.lua` para incluir as novas regras:

```lua
ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    include = '/etc/snort/rules/local.rules',
    include = '/etc/snort/rules/snort3-content-replace.rules',
    include = '/etc/snort/rules/snort3-file-flash.rules',
}
```

## Executando o Snort e Verificando Logs

Para iniciar o Snort, use:

```bash
sudo snort -c /etc/snort/snort.lua -i <interface> -A fast -l /var/log/snort
```

> Substitua `<interface>` pelo nome da interface de rede (por exemplo, `eth0` ou `wlan0`).

Para monitorar os alertas registrados:

```bash
tail -f /var/log/snort/alert_fast.txt
```

## Conclusão

Com o Snort instalado e configurado, você agora possui uma poderosa ferramenta de detecção de intrusão para monitorar e proteger sua rede. Expanda as regras e configurações conforme necessário para atender às necessidades específicas de segurança do seu ambiente.
```

Este README em Markdown fornece uma estrutura clara e organizada para documentar o processo de instalação e configuração do Snort 3 no GitHub, com detalhes suficientes para orientar usuários no processo de implementação e personalização de regras.
