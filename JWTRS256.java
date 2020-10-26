import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64URL;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Geração de JWT
 * 
 * @author Thiago Pellegrino | Wesley Gonzaga | Aécio Santiago
 *
 */
public class JWTRS256 {

	// PAYLOAD
	private static String payload = "{\r\n" + "  \"txId\": \"52c43361-caa1-4ddb-9152-708426a25db3\",\r\n"
			+ "  \"revisao\": \"3\",\r\n" + "  \"calendario\": {\r\n"
			+ "    \"criacao\": \"2020-09-15T19:39:54.013Z\",\r\n"
			+ "    \"apresentacao\": \"2020-04-01T18:00:00Z\",\r\n" + "    \"expiracao\": \"1200\"\r\n" + "  },\r\n"
			+ "  \"valor\": {\r\n" + "    \"original\": \"500.00\"\r\n" + "  },\r\n"
			+ "  \"chave\": \"7407c9c8-f78b-11ea-adc1-0242ac120002\",\r\n"
			+ "  \"solicitacaoPagador\": \"Informar cartão fidelidade\",\r\n" + "  \"infoAdicionais\": [\r\n"
			+ "    {\r\n" + "      \"nome\": \"quantidade\",\r\n" + "      \"valor\": \"2\"\r\n" + "    }\r\n"
			+ "  ]\r\n" + "}";

	public static void main(String[] args) {

		Header<?> header = Jwts.header();
		header.setType("JWT");

		// KID DO JWT
		String kid = UUID.randomUUID().toString();

		String algoritmo = SignatureAlgorithm.RS256.toString();

		// THUMBPRINT EM SHA1 DA PRIVATEKEY
		Base64URL x5t = Base64URL.encode("e853f70e43cc6505ee74057106ae638da73cc281");

		// CERTIFICATE
		String x5c = "MIIC1DCCAbygAwIBAgIGAXUsDoQzMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMM"
				+ "IDRGVlJ1YlZPbWg4M1E2VkE4biUyQmpldVZ5c2ZrJTNEMB4XDTIwMTAxNTExMzkx"
				+ "MFoXDTIxMDgxMTExMzkxMFowKzEpMCcGA1UEAwwgNEZWUnViVk9taDgzUTZWQThu"
				+ "JTJCamV1VnlzZmslM0QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo"
				+ "mqSgo1eNCLgceDYGGVn15X6Jk3HJSS6alq3RWS2mC6GYpG3Pn6n24F5nE8U0Xpji"
				+ "jGDDOGt97pcKnPWKI+fOKktqyNlCrUQ/JzpkDh3Z1sXD4nO0MEUzVuTvo/ToXL6U"
				+ "z6z1l3d8qKH902UbJZlsS6+YqRP99TZtVdmN+fJEgL1NSzftp7qWDFRV8RSG4iSk"
				+ "CZ38HGC9ebdBINug3FI5Mo2ANXpHYugzpB8u6XIpLWODugauikWcZJJxtgv1RU0m"
				+ "34fu+hZFB+jHDgQknI2OqalF1SaEkU5o7Eag9zfESkyauw+5cxb2wQxfezkpYUng"
				+ "EFsHvs0Wyrt9z+ztQ/ZTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADKaUttUUNCe"
				+ "1qjpeIfOCn7G3RTGaS0tdQOBUsjhJmwO8QjPvE5awSu5lpvZbzUQ95C5qIMYAi8K"
				+ "jPaPREfIW8wNQ8x6snKczPQKQ4YhLiOsvQYtON7MWzJic0ulZWf+69z+8uWm1sQd"
				+ "qIHox6Rmm9ZFHVEqlhjVF+LNUSxUI8MtdN+uZoQXbrP8HNB8BpXPbj86+HzBZgxD"
				+ "HFKOrRrSBfY6+71Zwejri3h7MvYEqntlVrmyNJkQR7Tk7S0PuKhWw8OJcPCE2zLR"
				+ "K5slx9IRgjsW1OE97fxMd9wzQhnHi2YFnzNiI9RM+9/YtrRNTbOjedjOyOzsMqrJ" + "H71xsGH1tXY=";

		// LISTA DE CERTIFICADOS
		JSONArray x509 = new JSONArray();
		x509.add(x5c);

		// ALGORITMOS RS OU PS
		JSONObject jwkRSPS = new JSONObject();
		jwkRSPS.put("kty", "RSA");
		jwkRSPS.put("e", "AQAB");
		jwkRSPS.put("n","qJqkoKNXjQi4HHg2BhlZ9eV-iZNxyUkumpat0VktpguhmKRtz5-p9uBeZxPFNF6Y4oxgwzhrfe6XCpz1iiPnzipLasjZQq1EPyc6ZA4d2dbFw-JztDBFM1bk76P06Fy-lM-s9Zd3fKih_dNlGyWZbEuvmKkT_fU2bVXZjfnyRIC9TUs37ae6lgxUVfEUhuIkpAmd_BxgvXm3QSDboNxSOTKNgDV6R2LoM6QfLulyKS1jg7oGropFnGSScbYL9UVNJt-H7voWRQfoxw4EJJyNjqmpRdUmhJFOaOxGoPc3xEpMmrsPuXMW9sEMX3s5KWFJ4BBbB77NFsq7fc_s7UP2Uw");
		jwkRSPS.put("kid", kid);
		jwkRSPS.put("alg", algoritmo);
		jwkRSPS.put("x5c", x509);
		
		// PRIVATEKEY
		String PRIVATEKEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQComqSgo1eNCLgc"
				+ "eDYGGVn15X6Jk3HJSS6alq3RWS2mC6GYpG3Pn6n24F5nE8U0XpjijGDDOGt97pcK"
				+ "nPWKI+fOKktqyNlCrUQ/JzpkDh3Z1sXD4nO0MEUzVuTvo/ToXL6Uz6z1l3d8qKH9"
				+ "02UbJZlsS6+YqRP99TZtVdmN+fJEgL1NSzftp7qWDFRV8RSG4iSkCZ38HGC9ebdB"
				+ "INug3FI5Mo2ANXpHYugzpB8u6XIpLWODugauikWcZJJxtgv1RU0m34fu+hZFB+jH"
				+ "DgQknI2OqalF1SaEkU5o7Eag9zfESkyauw+5cxb2wQxfezkpYUngEFsHvs0Wyrt9"
				+ "z+ztQ/ZTAgMBAAECggEAfgjLk4FGyxh/eFisGbcNtnDNPE5JuqvH+Ks2V84P/5Wm"
				+ "QJJ5u8Cgrvld2DPBMLqeEovZMVWVlNerdLWMHq1kdIrNQY/OSLd40rSiQ3UB/3s6"
				+ "7ojy8Pk8YXpNPI4VXzUlCdyMcDG/kiIEpddGNxrOK1QQeU+6sBaDjwujyyvSXD2c"
				+ "FDn2W/eRR59k51lwikLeCIVUNg9icVQSBjTKgYrV3KENFPpoeVKV505+C5hYBnNx"
				+ "O+kh/0uzqXXBkTZsmo2Z9teWYXqTEyIQRsjne8rBJd0fFkUlOk5EUbtRS1Kg+stF"
				+ "29/9rWDMw67CozJyitROjXD3oxKkqyu6hrQPRLgnIQKBgQD7DWXy6O6dT+5UknYu"
				+ "S7m/jEoQbj7RZJuLFZLMlYopPkTkxUC5/3CR+2YOKYuZZkD+GqONhLx2VEoo0uFe"
				+ "s/pMPEF6UGz/H6Utkf7C9Vy6BFmrBDqdjyT2AbyPbP2dqJheTi1osAkxhluf4fq7"
				+ "cZF5Vk51RuhJqc8xahhfNhJfiwKBgQCr7UeBysL5Q3rgF8Q5lIyb7Cj1g7rhan8H"
				+ "bC4qhLl48cdjfdSF0aUbbBv3x/QtcVA/aeP+seZgELcfJAe962I+gKfppBsrnw0z"
				+ "1F7D6fULMHEjn0aYIvYbzro6tL5aYVxf6DaGHnsJCyCcq4s5yiDNslzMWK5BzdzA"
				+ "gRBeBeodWQKBgFQC0MnvzuHPvLaKaIfniVojLSnAar8RhseNSZmytRBGKTHRHG7h"
				+ "nx8K3MUCfBeyUy91ZKPX9mU2obZ1kztoyOq4A0VWIpNhWJoeT/2XtBb/m64R9TeC"
				+ "jmDQhfQNCfW3VH3CdYmh1wG+r2yaZ5hQUdkj2499UgBMlew4T72Uz6MvAoGAD/SL"
				+ "SE5K3dsXUiiiez1/9xBplK9O7pB1jXjKqAN9Ou4lNOR+jpSwH+VeixYxYO49JkVr"
				+ "dT2JRa0HcYpkdYmcqnRCIPqr0taF4SN6T/AsX4d1WHr1kDTeZiI/Qid36udSLUxd"
				+ "kwDNJj+0HRYGa6yIcs50sjogoda6/9p6bF9cJLECgYEAqQ+d1AFlQTGfR4cr7Jwt"
				+ "edK4F3AneShB6WjYqzY/e8bmZuwHNDQi4qCsF9uUZ6XGroWaX3JvU14e8tIsdTMr"
				+ "Y+sldRBLcxmrJSPnGnEDNmbe/j3JTmbwEbuSw4HRJZIOs0Rn10Oh1SR2nMSBUF2L" + "4V8CRACqaJoMGOzwVKT2L4I=";

		PrivateKey priv = null;

		try {

			byte[] keyBytes = Base64.getDecoder().decode(PRIVATEKEY.getBytes());

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

			KeyFactory fact = KeyFactory.getInstance("RSA");

			priv = fact.generatePrivate(keySpec);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String jwtToken = Jwts.builder()
				.setHeaderParam("alg", algoritmo)
				.setHeaderParam("jku", "")
				.setHeaderParam("jwk", jwkRSPS)
				.setHeaderParam("x5t", x5t.toString())
				.setHeaderParam("kid", kid)
				.setPayload(payload)
				.signWith(SignatureAlgorithm.RS256, (Key) priv)
				.compact();

		System.out.println(jwtToken);
	}
}
