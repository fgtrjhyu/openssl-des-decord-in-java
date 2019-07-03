import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OpenSSLDecryptor {

  /**
   * 暗号化アルゴリズムがAES(128)で,メッセージダイジェストがSHA-256の場合の復号化コンテキスト.
   */
  public static final OpenSSLDecryptor AES_SHA256 = new OpenSSLDecryptor("AES", "SHA-256", 16);

  /**
   * 暗号化アルゴリズムがDESで,メッセージダイジェストがMD5の場合の復号化コンテキスト.
   */
  public static final OpenSSLDecryptor DES_MD5 = new OpenSSLDecryptor("DES", "MD5", 8);

  /**
   * 暗号化アルゴリズムがDESで,メッセージダイジェストがSHA-256の場合の復号化コンテキスト.
   */
  public static final OpenSSLDecryptor DES_SHA256 = new OpenSSLDecryptor("DES", "SHA-256", 8);

  /**
   * Salted__
   */
  private static final byte[] Salted__ = "Salted__".getBytes();

  /**
   * OpenSSLのencコマンドによるSalted(塩を振った?)暗号文を復号する<br>
   * <p>
   * Saltedな構造とは... <code>"Salted__" salt[8] ciphertext[*]</code> である.<br>
   * <p>
   * salt[8]とpassphrase[*]を使って暗号化の際に用いた関数でハッシュ値のbsバイト/ブロックの先頭2ブロックを秘密鍵と初期ベクタとして使用する.<br>
   * <code>(skey[bs], ivec[bs], _) = digest(passphrase[*].salt[8])</code><br>
   * 
   * @param msg  暗号文
   * @param pass パスフレーズ
   * @param cip  暗号文に使用した暗号化アルゴリズム
   * @param alg  秘密鍵に使用するアルゴリズム名
   * @param md   Salt化に使用した暗号学的ハッシュ関数
   * @param bs   Salt化で用いたキー長と初期ベクタ長を示すブロックサイズ
   * @return 平文
   * @throws Exception 色々な例外が発生する
   */
  public static byte[] decrypt(byte[] msg, byte[] pass, Cipher cip, String alg, MessageDigest md, int bs) throws Exception {
    if (!eq(msg, 0, Salted__, 0, sizeof(Salted__))) { // starts with "Salted_".
      throw new IllegalArgumentException("this ciphertext is not salted.");
    }
    md.reset();
    md.update(pass);
    md.update(msg, Salted__.length, 8);
    byte[] digest = md.digest();
    cip.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digest, 0, bs, alg), new IvParameterSpec(digest, bs, bs));
    return cip.doFinal(msg, 16, sizeof(msg) - 16);
  }

  /**
   * 2つのバイト配列の部分配列の要素が全て等しいかどうかを検査する.
   * 
   * @param xs  xsバイト配列
   * @param x   xs位置
   * @param ys  ysバイト配列
   * @param y   ys位置
   * @param len 比較する長さ
   * @return 全ての要素が等しければ true, そうでなければ false
   */
  private static boolean eq(byte[] xs, int x, byte[] ys, int y, int len) {
    return numeqs(xs, x, ys, y, len) == len;
  }

  public static void main(String[] args) throws Exception {
    System.err.println(AES_SHA256.decrypt("U2FsdGVkX1/rDTaN7Cv5vEBKP3OfNQHg1uH6EbdnmTs=", "MyKey"));
    System.err.println(DES_SHA256.decrypt("U2FsdGVkX1/e1a/t6RyYzJtTZljWi9K9eSC0271OihI=", "MyKey"));
    System.err.println(DES_MD5.decrypt("U2FsdGVkX18GLG/GM75IqXZLRA+a02/9qorSdr6qLl0=", "MyKey"));
  }

  /**
   * 2つのバイト配列中の部分配列の要素が何個分等しいか数える.
   * 
   * @param xs  xsバイト配列
   * @param x   xs位置
   * @param ys  ysバイト配列
   * @param y   ys位置
   * @param len 比較する長さ
   * @return 要素が等しい個数
   */
  private static int numeqs(byte[] xs, int x, byte[] ys, int y, int len) {
    int i = 0;
    final int lsz = sizeof(xs), rsz = sizeof(ys);
    for (; (x < lsz) && (y < rsz) && (xs[x] == ys[y]) && (i < len); ++i, ++x, ++y)
      ;
    return i;
  }

  /**
   * 配列の長さを取得する,nullを受け付け0を返却する.
   * 
   * @param a 配列
   * @return 配列の長さ nullならば0, 配列の長さ
   */
  private static int sizeof(byte[] a) {
    return a != null ? a.length : 0;
  }

  /**
   * 暗号化アルゴリズム(AES,DES)
   */
  private final String alg;

  /**
   * 秘密鍵と初期ベクタに使用するバイト数
   */
  private final int bs;

  /**
   * メッセージダイジェストに使用するアルゴリズム
   */
  private final String md;

  /**
   * 
   * @param alg 暗号化アルゴリズム
   * @param md  メッセージダイジェスト
   * @param bs  ブロックサイズ
   */
  public OpenSSLDecryptor(String alg, String md, int bs) {
    this.alg = alg;
    this.md = md;
    this.bs = bs;
  }

  /**
   * 暗号文を平文に複合します.
   * 
   * @param message    暗号文
   * @param passphrase パスフレーズ
   * @return 平文
   * @throws Exception
   */
  public String decrypt(String message, String passphrase) throws Exception {
    return decrypt(message, passphrase, Charset.defaultCharset());
  }

  /**
   * 暗号文を平文に複合します.
   * 
   * @param message    暗号文
   * @param passphrase パスフレーズ
   * @param cs         文字セット
   * @return 平文
   * @throws Exception
   */
  public String decrypt(String message, String passphrase, Charset cs) throws Exception {
    Cipher cip = Cipher.getInstance(String.format("%s/CBC/PKCS5Padding", this.alg));
    MessageDigest md = MessageDigest.getInstance(this.md);
    Decoder base64 = Base64.getDecoder();
    return new String(decrypt(base64.decode(message), passphrase.getBytes(cs), cip, this.alg, md, bs), cs);
  }
}
