import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

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
public class JWTEC256 {

	// PAYLOAD
	private static String payload = "{" + "  \"txId\": \"ES256361-caa1-4ddb-9152-708426a25db3\","
			+ "  \"revisao\": \"3\"," + "  \"calendario\": {" + "    \"criacao\": \"2020-09-15T19:39:54.013Z\","
			+ "    \"apresentacao\": \"2020-04-01T18:00:00Z\"," + "    \"expiracao\": \"1200\"" + "  },"
			+ "  \"valor\": {" + "    \"original\": \"500.00\"" + "  },"
			+ "  \"chave\": \"7407c9c8-f78b-11ea-adc1-0242ac120002\","
			+ "  \"solicitacaoPagador\": \"Informar cartão fidelidade\"," + "  \"infoAdicionais\": [" + "    {"
			+ "      \"nome\": \"quantidade\"," + "      \"valor\": \"2\"" + "    }" + "  ]" + "}";

	public static void main(String[] args) {

		Header<?> header = Jwts.header();
		header.setType("JWT");

		// KID DO JWT
		String kid = "R/nX3GOhzPbiPhS7kC0bg2pBjsE=";// UUID.randomUUID().toString();

		String algoritmo = SignatureAlgorithm.ES256.toString();

		// THUMBPRINT EM SHA1 DA PRIVATEKEY
		Base64URL x5t = Base64URL.encode("fe5f5bc6c9c60e6c8eef1d0038df90a655ef556f");

		// CERTIFICATE
		String x5c = "MIIBSDCB7qADAgECAgYBdTvcqpQwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgUiUy" + 
				"Rm5YM0dPaHpQYmlQaFM3a0MwYmcycEJqc0UlM0QwHhcNMjAxMDE4MTMxODM4WhcN" + 
				"MjEwODE0MTMxODM4WjArMSkwJwYDVQQDDCBSJTJGblgzR09oelBiaVBoUzdrQzBi" + 
				"ZzJwQmpzRSUzRDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGzYLv0rq/Q0NnfL" + 
				"tAsocrAGw8GnKM20/Qslri62y+Mb4Kk4MbEgFfwsflEDCrMqcT9bXY0QeUNvq9jL" + 
				"0boAA+UwCgYIKoZIzj0EAwIDSQAwRgIhAOoMkIscOx+ldCvbxrb/SVFOQvPJ0xt0" + 
				"ZgXBNaTtEWBXAiEA5GfO5G7SbvLMQINRGwdiS/8xBYDo4d4pY6Yz1ff41F8=";

		// LISTA DE CERTIFICADOS
		JSONArray x509 = new JSONArray();
		x509.add(x5c);

		// ALGORITMOS ES
		JSONObject jwkES = new JSONObject();
		jwkES.put("kty", "EC");
		jwkES.put("d", "xHfw_dB6H-uw14qX329BLVzYBbxqfA2nj6O5HJTvSms");
		jwkES.put("crv", "P-256");
		jwkES.put("x", "bNgu_Sur9DQ2d8u0CyhysAbDwacozbT9CyWuLrbL4xs");
		jwkES.put("y", "4Kk4MbEgFfwsflEDCrMqcT9bXY0QeUNvq9jL0boAA-U");
		jwkES.put("use", "sig");
		jwkES.put("kid", kid);
		jwkES.put("x5c", x509);		
		jwkES.put("alg","ES256");

		// PRIVATEKEY
		String PRIVATEKEY = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDEd/D90Hof67DXipff" + 
				"b0EtXNgFvGp8DaePo7kclO9Kaw==";

		PrivateKey priv = null;

		try {

			byte[] keyBytes = Base64.getDecoder().decode(PRIVATEKEY.getBytes());

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

			KeyFactory fact = KeyFactory.getInstance("EC");

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
				.setHeaderParam("jwk", jwkES)
				.setHeaderParam("x5t", x5t.toString())
				.setHeaderParam("kid", kid)
				.setPayload(payload)
				.signWith(SignatureAlgorithm.ES256, (Key) priv)
				.compact();

		System.out.println(jwtToken);
	}
}
