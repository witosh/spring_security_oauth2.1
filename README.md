# Oauth2.1
### Spring Authorization Server is a framework that provides implementations of the OAuth 2.1 

### Prepare data for auth by authorization_code grant type

## Create code_verifier and code_challenge for authorization:
According to: [rfc7636](https://www.rfc-editor.org/rfc/rfc7636#section-4.1):
- **code_verifier** must contain minimum length of 43 characters
and 
- **code_challenge** = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))

if use **code_challenge_method=S256**

For example:
- **code_verifier** = jzCwwxWaTjHgfmRdSrqIKtwmlkMgnRHxqThMhvbBA6v 

Let's generate code_challenge to:
https://tonyxu-io.github.io/pkce-generator/
- **code_challenge** = 9fvES2n_rFe1h3c82_eVAUWAmk182mEuxCMK3YK-2WQ

Flow:
```
http://127.0.0.1:8080/oauth2/authorize?
response_type=code&
client_id=client&
scope=openid&
redirect_uri=http://spring.io/auth&
code_challenge=9fvES2n_rFe1h3c82_eVAUWAmk182mEuxCMK3YK-2WQ&
code_challenge_method=S256
```

we get will be redirect according to redirect_uri parameter and in uri there will be **code**. That code is authorization_code from that grant type

and the n postman or curl:
```
curl  -XPOST 'http://127.0.0.1:8080/oauth2/token?client_id=client&redirect_uri=http://spring.io/auth&grant_type=authorization_code&code=ce7osXDDkuXlvQ0EzBOt-pYqk16Z0L6dZ6sxjRSqSfxDBykNgMXyUw7sfn2PABssDLnsXG14BgU8pW-O7sh45AriQvfe4Q9QXKVHqwyeszYDXsBLGJEsw-0DLvuyKk_V&code_verifier=jzCwwxWaTjHgfmRdSrqIKtwmlkMgnRHxqThMhvbBA6v' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='

```
