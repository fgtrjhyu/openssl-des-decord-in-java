import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

  private static final byte[] MAGIC_SALTED = "Salted__".getBytes();

  /**
   * OpenSSLのencコマンドによるSalted(?)な暗号文を復号する<br>
   * <p>
   * Saltedな構造とは... <code>"Salted__" salt[8] body[*]</code> である.<br>
   * <p>
   * saltとpassphraseを使って符号化の際に用いた関数によるハッシュ値をnバイト/ブロックの先頭2ブロックを秘密鍵と初期ベクタとして使用する.<br>
   * <code>(skey[n], ivec[n], _) = digest(passphrase[*].salt[8])</code><br>
   * 
   * @param cipher     暗号スイート
   * @param md         メッセージダイジェスト
   * @param alg        秘密鍵のアルゴリズム
   * @param len        キー長と初期ベクタ長
   * @param encoded    暗号
   * @param passphrase パスフレーズ
   * @return 平文
   * @throws Exception 色々な例外が発生する
   */
  public static byte[] decrypt(Cipher cipher, MessageDigest md, String alg, int len, byte[] encoded, byte[] passphrase) throws Exception {
    if (!eq(encoded, 0, MAGIC_SALTED, 0, sizeof(MAGIC_SALTED))) { // starts with "Salted_".
      throw new IllegalArgumentException("Invalid Data Format.");
    }
    md.reset();
    md.update(passphrase);
    md.update(encoded, sizeof(MAGIC_SALTED), 8);
    byte[] digest = md.digest();
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(digest, 0, len, alg), new IvParameterSpec(digest, len, len));
    return cipher.doFinal(encoded, 16, sizeof(encoded) - 16);
  }

  /**
   * 2つのバイト配列の部分配列の要素が全て等しいかどうかを検査する.
   * 
   * @param left  左バイト配列
   * @param lpos  左バイト配列の開始位置
   * @param right 右バイト配列
   * @param rpos  右バイト配列の開始位置
   * @param len   比較する長さ
   * @return 全ての要素が等しければ true, そうでなければ false
   */
  private static boolean eq(byte[] left, int lpos, byte[] right, int rpos, int len) {
    return eqth(left, lpos, right, rpos, len) == len;
  }

  /**
   * 2つのバイト配列中の部分配列の要素が先頭から何個分等しいか数える.
   * 
   * @param left  左バイト配列
   * @param lpos  左バイト配列の開始位置
   * @param right 右バイト配列
   * @param rpos  右バイト配列の開始位置
   * @param len   比較する長さ
   * @return 要素が等しい個数
   */
  private static int eqth(byte[] left, int lpos, byte[] right, int rpos, int len) {
    int i = 0;
    for (int lsz = sizeof(left), rsz = sizeof(right); i < len; ++i, ++lpos, ++rpos) {
      if (!((lpos < lsz) && (rpos < rsz) && (left[lpos] == right[rpos]))) {
        break;
      }
    }
    return i;
  }

  public static void main(String[] args) throws Exception {
    Cipher desCbc = Cipher.getInstance("DES/CBC/PKCS5Padding");
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    String text = "U2FsdGVkX19Bsru7xG/2xhseKk0TR1bBX0YnIqfv3Tg=";
    String password = "MyKey";
    byte[] plain = decrypt(desCbc, sha256, "DES", 8, Base64.getDecoder().decode(text), password.getBytes());
    System.err.println(new String(plain));
  }

  private static int sizeof(byte[] a) {
    return a != null ? a.length : 0;
  }
}
