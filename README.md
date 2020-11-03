# jwt
Geração de JWT para o Pix-BR

Esses são simples exemplos de como devem ser gerados os JWTs conforme cada um dos 09 algoritmos aprovados na versão do 1.1 do Manual de Iniciação do Bacen para o padrão Pix BRCode - QRCode Dinâmico, contemplando todos os atributos mínimos necessários para as validações de segurança.

Vamos seguir o passo a passo para gerarmos os JWTs (cada qual com seu devido algoritmo) conforme o manual de segurança do Bacen:

              1 - https://mkjwk.org/ aqui geramos a PrivateKey / PublicKey / Certificate, para isso é preciso selecionar:
              Algoritmo(PS|RS para RSA e ES para EC)
              KeyUse como Signature
              KeyID SHA-1
              Show X.509 Yes. 
              
              Com isso devemos passar o Certificate no campo x5c em formato JSONArray e o PrivateKey na assinatura do JWS.
              Importante lembrar qual algoritmo está selecionado para utiliza-lo novamente na assinatura do JWT.

              2 - https://www.venea.net/web/hash_function agora geramos o hash do certificado em SHA-1 para o thumbprint da PrivateKey utilizada que será o valor do campo x5t.

              3 – Nas classes RS256 | PS256 | ES256  basta preencher os campos conforme os atributos do JSON apresentado no item 1.
              Lembrando de substituir o algoritmo referente as chaves geradas.

              4 – Basta executar o código e copiar o JWT Assinado para que possa verificar sua estrutura em http://jwt.io  
