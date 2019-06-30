import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	private static final byte[] SALTED_MAGIC = "Salted__".getBytes();

	private static int add(int... list) {
		int r = 0;
		for (int e : list) {
			r += e;
		}
		return r;
	}

	private static byte[] concat(byte[]... list) {
		byte[] r = new byte[add(mapSizeof(list))];
		int offset = 0;
		for (byte[] e : list) {
			System.arraycopy(e, 0, r, offset, e.length);
			offset += e.length;
		}
		return r;
	}

	/**
	 * OpenSSLのencコマンドによるSaltedな暗号文を復号する
	 * 
	 * @param c    暗号スイート
	 * @param md   メッセージダイジェスト
	 * @param alg  秘密鍵のアルゴリズム
	 * @param klen キー長と初期ベクタ長
	 * @param enc  暗号
	 * @param pwd  パスワード
	 * @return 平文
	 * @throws Exception 色々な例外が発生する
	 */
	public static byte[] decrypt(Cipher c, MessageDigest md, String alg, int klen, byte[] enc, byte[] pwd)
			throws Exception {
		// data[0]: "Salted__", data[1]: salt, data[2]: body
		byte[][] data = split(enc, 8, 8, enc.length - 16);
		if (!Arrays.equals(data[0], SALTED_MAGIC)) {// Satled__から始まらない
			throw new IllegalArgumentException("Invalid Data Format.");
		}
		// digest値の先頭から klen 個のバイト列が秘密鍵で, その後方 klen 個のバイト列が初期ベクタである
		byte[] digest = md.digest(concat(pwd, data[1]));
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digest, 0, klen, alg), new IvParameterSpec(digest, klen, klen));
		return c.doFinal(data[2]);
	}

	public static void main(String[] args) throws Exception {
		Cipher desCbc = Cipher.getInstance("DES/CBC/PKCS5Padding");
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		String text = "U2FsdGVkX19Bsru7xG/2xhseKk0TR1bBX0YnIqfv3Tg=";
		String password = "MyKey";
		byte[] plain = decrypt(desCbc, sha256, "DES", 8, Base64.getDecoder().decode(text), password.getBytes());
		System.err.println(new String(plain));
	}

	private static int[] mapSizeof(byte[][] list) {
		int[] r = new int[sizeof(list)];
		for (int i = 0, end = list.length; i < end; ++i) {
			r[i] = sizeof(list[i]);
		}
		return r;
	}

	private static int sizeof(byte[] a) {
		return a != null ? a.length : 0;
	}

	private static int sizeof(Object[] a) {
		return a != null ? a.length : 0;
	}

	private static byte[][] split(byte[] data, int... nlen) {
		byte[][] r = new byte[nlen.length][];
		for (int i = 0, end = nlen.length, offset = 0; i < end; offset += nlen[i], ++i) {
			System.arraycopy(data, offset, (r[i] = new byte[nlen[i]]), 0, nlen[i]);
		}
		return r;
	}

}
