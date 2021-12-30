# Trabalho realizado na Semana #3

## Identificação - CVE-2019-3929

- A vulnerabilidade deve-se ao fraco tratamento de inputs aquando do parsing de *HTTP requests*
- User não autenticado pode executar comandos do sistema operativo como root
- Os dispositivos afetados tratam-se de *wireless presentation devices*, tais como o Crestron AM-100, mais concretamente na sua firmware.
- Plataformas: The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10 etc.

## Catalogação

- Autor: Jacob Baines - METASPLOIT, 30-04-2019
- Severidade: 9.8/10 de acordo com NIST
- Possíveis danos: divulgação total de informações, integridade do sistema comprometida, encerramento total do sistema
- Como solução, alguns firmwares foram descontinuados e outros atualizados

## Exploit

- OS command injection através de uma vulnerabilidade explorada com *HTTP request*
- Automação através da plataforma METASPLOIT - https://www.exploit-db.com/exploits/47924
- Modo de uso: baixa complexidade, não existem condições de acesso especiais ou circunstâncias atenuantes, autenticação não é necessária

## Ataques

- Ataques bem sucedidos: The Crestron AM-100 firmware 1.6.0.2, Crestron AM-101 firmware 2.7.0.1, Barco wePresent WiPG-1000P firmware 2.3.0.10 etc. (*Documentação de ataque* https://www.fortiguard.com/encyclopedia/ips/47830)
- Potencial ataque de denial of service - com acesso como root pode impedir-se que o dispositivo apresente a informação
- Roubo de dados retransmitindo o que recebe para um endereço escolhido pelo atacante
- Injeção de spyware e outros malwares 
