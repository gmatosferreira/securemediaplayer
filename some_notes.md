#client and server
Para produzir música o cliente conta com ffplay  do ffmpeg project.
O cliente irá buscar dados do server em pedaços e irá escrever cada pedaço no ffplay, evitando persistência no hard disck.

Objetivos:
Segurança de comunicação entre o cliente e o server.


#server
Tem uma lista de media titles que podem ser listados e produzidos por um periodo específico.
O resultado é a criação de um token que permite ao user ter acesso ao media file durante algum tempo OU por um número limitado de visualizações.


(Existe um content distributor) que assegura a autenticidade do conteúdo, um cliente, servidor e um user).

#client
Será capaz de listar e rent titles.
Terá que ter a licença antes da media.
Licenças serão objetos criptados, criados pelo servidor permitinfo ao user ter acesso ao file.

Os clientes não irão guardar data e os conteudos serão dados para o media player diretamente.

Cada pedaço transmitido terá uma chaves individuais.
A key derivation mechanism is to be selected by
the students, ranging from a hash chain based scheme, counters, or asymmetric cryptography (to name a few).

