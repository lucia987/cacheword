package jni;

import info.guardianproject.cacheword.Constants;
import info.guardianproject.cacheword.Wiper;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.util.Log;

public class PrivateData {
    private static String newPassphrase;
    private static HashSet<PrivateDataHandler> handlers = new HashSet<PrivateDataHandler>();
    
    public static PrivateDataHandler add(Object obj) {

        Log.d("LUCIA", "PrivateData.add()");
        PrivateDataHandler handler = new PrivateDataHandler(obj);
        handlers.add(handler);
        return handler;
    }

    /* TODO: Provide C alternative */
	public static PrivateDataHandler PassphraseSecrets$hashPassphrase(
			PrivateDataHandler x_password_handler, byte[] salt) throws GeneralSecurityException {
		char[] x_password = (char[]) x_password_handler.getData();
		PBEKeySpec x_spec = null;
        try {
            x_spec                   = new PBEKeySpec(x_password, salt, Constants.PBKDF2_ITER_COUNT, Constants.PBKDF2_KEY_LEN);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            return PrivateData.add(new SecretKeySpec(factory.generateSecret(x_spec).getEncoded(), "AES"));
        } finally {
            Wiper.wipe(x_spec);
        }
	}


    /* TODO: Provide C alternative */
	public static byte[] PassphraseSecrets$decryptSecretKey(
			PrivateDataHandler x_passphraseKeyHandler, byte[] iv, byte[] ciphertext) 
					throws GeneralSecurityException {
		SecretKey x_passphraseKey = (SecretKey) x_passphraseKeyHandler.getData();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(ciphertext);
    }


    /* TODO: Provide C alternative */
	public static byte[] PassphraseSecrets$encryptSecretKey(
			PrivateDataHandler x_passphraseKeyHandler, byte[] iv, byte[] data) throws GeneralSecurityException {
		SecretKey x_passphraseKey = (SecretKey) x_passphraseKeyHandler.getData();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // TODO(abel) follow this rabbit hole down and wipe it!
        cipher.init(Cipher.ENCRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(data);
    }
}

