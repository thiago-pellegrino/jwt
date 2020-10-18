import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64URL;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Geração de JWT
 * 
 * @author Thiago Pellegrino | Wesley Gonzaga | Aécio Santiago
 *
 */
public class JWTPS256 {

	// PAYLOAD
	private static String payLoad = "{\r\n" + "  \"txId\": \"PS256361-caa1-4ddb-9152-708426a25db3\",\r\n"
			+ "  \"revisao\": \"3\",\r\n" + "  \"calendario\": {\r\n"
			+ "    \"criacao\": \"2020-09-15T19:39:54.013Z\",\r\n"
			+ "    \"apresentacao\": \"2020-04-01T18:00:00Z\",\r\n" + "    \"expiracao\": \"1200\"\r\n" + "  },\r\n"
			+ "  \"valor\": {\r\n" + "    \"original\": \"500.00\"\r\n" + "  },\r\n"
			+ "  \"chave\": \"7407c9c8-f78b-11ea-adc1-0242ac120002\",\r\n"
			+ "  \"solicitacaoPagador\": \"Informar cartão fidelidade\",\r\n" + "  \"infoAdicionais\": [\r\n"
			+ "    {\r\n" + "      \"nome\": \"quantidade\",\r\n" + "      \"valor\": \"2\"\r\n" + "    }\r\n"
			+ "  ]\r\n" + "}";

	public static void main(String[] args) {

		// KID DO JWT
		String kid = "EQRwpU6X4EC6TxjBnN+fRfoZ15E=";// UUID.randomUUID().toString();

		String algoritmo = SignatureAlgorithm.PS256.toString();

		// SHA1
		Base64URL x5t = Base64URL.encode("dfd64ce2088a8fc03454bb317e13bb5dee7dd92c");

		// CERTIFICATE
		String x5c = "-----BEGIN CERTIFICATE-----\r\n"
				+ "MIIC1DCCAbygAwIBAgIGAXUyKWeFMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMM\r\n"
				+ "IEVRUndwVTZYNEVDNlR4akJuTiUyQmZSZm9aMTVFJTNEMB4XDTIwMTAxNjE2MDYx\r\n"
				+ "NVoXDTIxMDgxMjE2MDYxNVowKzEpMCcGA1UEAwwgRVFSd3BVNlg0RUM2VHhqQm5O\r\n"
				+ "JTJCZlJmb1oxNUUlM0QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc\r\n"
				+ "K3HaAsnfycnE/OpGUrnNyM5R+deYpVBVaQ8rPGTvWTvI2i+hm5/SIQ+Gewciz+TK\r\n"
				+ "UaIcTM20Nkc9f/1t3uSjDb/xEMcCvbD/92ar/nXF56t0T1gSk0JmKiLZGgWgiM/D\r\n"
				+ "MwTbZirIUhDkHcRiTKFGgsZX4HmyN2mP7H5ZRhfDmH0ghO9HPCbCCi8O+GbVrboX\r\n"
				+ "Vq+ZkLPqVn+GJRtraCaMk4N/JyluTGi9o0S2wg5wcJgo7sxnFFGjkoVu9tl3sJxE\r\n"
				+ "L67IbrAkKM3hhnOeU1mjumprZDVJAJ+KONgdKq1MsdAk8rRdR65o1go+CfUtEDRT\r\n"
				+ "SjOpklfJ8MeXV7UlAc9FAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAD1ebsTc6WqS\r\n"
				+ "dZqpJ2MHwaSe9eLplJazMDQblrqUjvUi1ZdSILRV9dk4/1cutS/n5sti1L/qQfQv\r\n"
				+ "UbmQpa25GyJKVK+blGO64/22DhvchKZNwpTEQsVIF/JQxPRn208Fdxtr+NZrnELx\r\n"
				+ "qRg7TrtK1EjeqdmQt41WU2bT6KY1/1hZo3lhPbQchukrCtynrGDk8KO7CadJJolz\r\n"
				+ "OKV7PW8SkX1Vq5wFQ9gJ+eCr7A7P0yRKTzK/BhXMvqfkIcyEbcfhcTnSz24ud45e\r\n"
				+ "9bMGzPugooT64sVmRmov703F9DOzSti5IsGV75MZJU9pQtsdMHwXEBgNVMiL4BUI\r\n" + "649YJICF8D4=\r\n"
				+ "-----END CERTIFICATE-----";
		
		// LISTA DE CERTIFICADOS
		List<String> x509 = new ArrayList<String>();
		x509.add(Base64URL.encode(x5c).toString());

		// ALGORITMOS RS OU PS
		JSONObject jwkRSPS = new JSONObject();
		jwkRSPS.put("kty", "RSA");
		jwkRSPS.put("e", "AQAB");
		jwkRSPS.put("n","nCtx2gLJ38nJxPzqRlK5zcjOUfnXmKVQVWkPKzxk71k7yNovoZuf0iEPhnsHIs_kylGiHEzNtDZHPX_9bd7kow2_8RDHAr2w__dmq_51xeerdE9YEpNCZioi2RoFoIjPwzME22YqyFIQ5B3EYkyhRoLGV-B5sjdpj-x-WUYXw5h9IITvRzwmwgovDvhm1a26F1avmZCz6lZ_hiUba2gmjJODfycpbkxovaNEtsIOcHCYKO7MZxRRo5KFbvbZd7CcRC-uyG6wJCjN4YZznlNZo7pqa2Q1SQCfijjYHSqtTLHQJPK0XUeuaNYKPgn1LRA0U0ozqZJXyfDHl1e1JQHPRQ");
		jwkRSPS.put("kid", kid);
		jwkRSPS.put("alg", algoritmo);
		jwkRSPS.put("x5c", x509);

		String PRIVATEKEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcK3HaAsnfycnE"
				+ "/OpGUrnNyM5R+deYpVBVaQ8rPGTvWTvI2i+hm5/SIQ+Gewciz+TKUaIcTM20Nkc9"
				+ "f/1t3uSjDb/xEMcCvbD/92ar/nXF56t0T1gSk0JmKiLZGgWgiM/DMwTbZirIUhDk"
				+ "HcRiTKFGgsZX4HmyN2mP7H5ZRhfDmH0ghO9HPCbCCi8O+GbVrboXVq+ZkLPqVn+G"
				+ "JRtraCaMk4N/JyluTGi9o0S2wg5wcJgo7sxnFFGjkoVu9tl3sJxEL67IbrAkKM3h"
				+ "hnOeU1mjumprZDVJAJ+KONgdKq1MsdAk8rRdR65o1go+CfUtEDRTSjOpklfJ8MeX"
				+ "V7UlAc9FAgMBAAECggEAOoFsHah9yIDoPgwiGEZVpWpdIQjgZCdKeTTqod/2UFS1"
				+ "uQFEZt7OeQI5tr/QZJJNvB3pBYEgbysGdVvFraubLBqylbUbWUOHU91zcWva41Fv"
				+ "QhuXex3/+hY/B+ZfxUx7yT0LzMXxsSpNeahNMiZTJP9JHxLRhJqNyYVnsDo6HOQj"
				+ "tXKVGGEP8U1vgTT9r3qAMfaJwlpdvN+8rc7pCqnTedQabDigeI1NnEMNQRRAUHaR"
				+ "3OB+opm/ZyAyyk4PgROmF1TFCDoNu4eSJlzPh2CCkOIm7NaYkg+AeHD/R9WvMptr"
				+ "u+5oJN1arRiTjClVbLLG3SuGG93SpXGNQNr+4wB74QKBgQDtYr3U//WBHYnMgjee"
				+ "9diEXX951fmGEVnN2mmvW9KTSSiQH/2bRwQSpxDMi/8oKQ3AGuohhRbR/obWCMcm"
				+ "oNR0EzwrEJT0dZlDTy3o5dv4hYdMCxiDZ43a5oOne1g2lOUwRz40oc+uCqd7XaEt"
				+ "GbsyBTN4yVyW223PHH5hxv4mgwKBgQCoamF6F1ToWYn4IG8LujX5dDPYVIW+lIel"
				+ "me1mSfHZ9gNjelLhTkKu6JqLeegBLDRbkF74F7SSvNKxYAE3umH2h0F2PH1UsJc9"
				+ "WeKILKmogaoR9TeJFX+WbaPCWV3GywpzvxHMMIaak4iOU6M9IIJu1AcuPq2Ng50N"
				+ "JEMDz3cIlwKBgAbmdOApJIjBRA0mx9keClImqZrwBlXIUVTzgVjwkVloqf4uf9+w"
				+ "m8SzCID5nMwdDWJFJgMdbEFkZaT5EljkGejZ2kjiLYJBnNfhCFOZwuAheYJTXD4N"
				+ "l4kCZFdM9Y54m4TgvUUoYvILKz0hxpqaAd/9WLatG7zi2flIOcA72Y1jAoGAEGkd"
				+ "SnpPibx/1y/B4lCoxb/u9Vt3FNUASsCvA1KdQHHabq0SumWX1ddQh9q/Iq4eA/YT"
				+ "avVUYSAJH8ONGtMMjKstU8odJE14zz+c9Uv01DieS9WrLa5smkngtSVkH+TVBeZO"
				+ "Y6ku1I0ft06rD1/FlesPMBBndOyoNwmbhhmHLc0CgYAHwsCdD6UAfpj6b7Eq5/k9"
				+ "KCw5vJ2xq4Qvck6Ltm1FYxg2zGQrzL4cgXbdHE2XUeOod1wDs2xIuce7X4j6pdlK"
				+ "Z1M31wm8O/F5KutWhIk9jyMkTQttg+E9OSAPVWyaQvm/mMNW9LujIqbrS4d1l7CZ" + "qGNthi1E1qCLqwrcf12Grw==";
		
		// PRIVATEKEY		
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

		String jwtToken = Jwts.builder().setHeaderParam("alg", algoritmo).setHeaderParam("jku", "")
				.setHeaderParam("jwk", jwkRSPS).setHeaderParam("x5t", x5t.toString()).setHeaderParam("kid", kid)
				.setPayload(payLoad).signWith(SignatureAlgorithm.PS256, (Key) priv).compact();

		System.out.println(jwtToken);

	}
}
