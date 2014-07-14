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

        Log.e("LUCIA", "PrivateData.add()");
        PrivateDataHandler handler = new PrivateDataHandler(obj);
        handlers.add(handler);
        return handler;
    }
    
    public static boolean LockScreenActivity$newEqualsConfirmation(
            PrivateDataHandler mHandler1, 
            PrivateDataHandler mHandler2) {

        Log.e("LUCIA", "PrivateData.LockScreenActivity$newEqualsConfirmation");
        return ((String)mHandler1.getData()).equals(
                (String)mHandler2.getData());
    }

    public static boolean LockScreenActivity$isPasswordFieldEmpty(PrivateDataHandler mHandler) {

        Log.e("LUCIA", "PrivateData.LockScreenActivity$isPasswordFieldEmpty");
        return ((String)mHandler.getData()).length() == 0;
    }

    public static PrivateDataHandler LockScreenActivity$isPasswordValid(
            PrivateDataHandler mHandler) {

        Log.e("LUCIA", "PrivateData.LockScreenActivity$isPasswordValid");
        char[] tmp = ((String)mHandler.getData()).toCharArray();
        PrivateDataHandler tmpHandler = add(tmp);
        return tmpHandler;
    }

    public static boolean LockScreenActivity$validatePassword(
            PrivateDataHandler handler, int minPassLength) {

        Log.e("LUCIA", "PrivateData.LockScreenActivity$validatePassword");
        char[] pass = (char[])handler.getData();
        return (pass.length < minPassLength && pass.length != 0);
    }

    public static boolean LockScreenActivity$initializeWithPassphrase1(
            PrivateDataHandler passphrase) {

        Log.e("LUCIA", "PrivateData.LockScreenActivity$initializeWithPassphrase1");
        return ((String)passphrase.getData()).isEmpty();
    }

    public static PrivateDataHandler LockScreenActivity$initializeWithPassphrase2(
            PrivateDataHandler passphrase) {
        Log.e("LUCIA", "PrivateData.LockScreenActivity$initializeWithPassphrase2");
        char[] tmp = ((String)passphrase.getData()).toCharArray();
        return add(tmp);
    }

    public static boolean LockScreenActivity$isConfirmationFieldEmpty(
            PrivateDataHandler mConfirmPassphraseHandler) {
        Log.e("LUCIA", "PrivateData.LockScreenActivity$isConfirmationFieldEmpty");
        return ((String)mConfirmPassphraseHandler.getData()).isEmpty();
    }

    /* TODO: Provide C alternative */
	public static PrivateDataHandler PassphraseSecrets$hashPassphrase(
			PrivateDataHandler x_password_handler, byte[] salt) throws GeneralSecurityException {
        Log.e("LUCIA", "PrivateData.PassphraseSecrets$hashPassphrase");

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
        Log.e("LUCIA", "PrivateData.PassphraseSecrets$decryptSecretKey");
		SecretKey x_passphraseKey = (SecretKey) x_passphraseKeyHandler.getData();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(ciphertext);
    }


    /* TODO: Provide C alternative */
	public static byte[] PassphraseSecrets$encryptSecretKey(
			PrivateDataHandler x_passphraseKeyHandler, byte[] iv, byte[] data) throws GeneralSecurityException {
        Log.e("LUCIA", "PrivateData.PassphraseSecrets$encryptSecretKey");
		SecretKey x_passphraseKey = (SecretKey) x_passphraseKeyHandler.getData();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // TODO(abel) follow this rabbit hole down and wipe it!
        cipher.init(Cipher.ENCRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(data);
    }
}

