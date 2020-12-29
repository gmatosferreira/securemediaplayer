# Gestão de Direitos Musicais

A base de dados de utilizadores está vazia. Devem ser criados novos utilizadores através do cliente, com recurso ao Cartão de Cidadão da República Portuguesa.

Os ficheiros do servidor estão encriptados com a chave armazenada no ficheiro `server/key.txt`. Para efeitos de teste é fornecido o script `server/encryptfiles.py`, que pode ser utilizado para os desencriptar.

```bash
# Exemplo para desencriptar a base de dados de licenças, que fica disponível no ficheiro licensesraw.txt
$ python encryptfiles.py licenses.json licensesraw.json d key.txt
```