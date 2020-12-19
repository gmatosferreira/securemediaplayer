# SIO | Digital Rights Management



## Antes de correr...

Tanto o *script* do servidor como o do cliente devem ser executados a partir da pasta raiz do projeto.

```bash
$ pwd
# Deve retornar (...)/sio_project
```

Antes dos executar, deve ser definida a variável de ambiente `PYTHONPATH`.

```bash
$ export PYTHONPATH=$(pwd)
$ echo $PYTHONPATH
# Deve retornar o mesmo que o comando $pwd
```

Feito isto, deve ser inicializado primeiro o servidor e só depois deste o cliente.

```bash
$ python server/server.py
# Esperar que servidor imprima chaves privada e pública
$ python client/client.py
```

