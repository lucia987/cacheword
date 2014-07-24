package jni;

import info.guardianproject.cacheword.Constants;
import info.guardianproject.cacheword.Wiper;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.util.Log;

public class TEEClient {
    private static String newPassphrase;
    private static HashSet<TEEObject> handlers = new HashSet<TEEObject>();
    
    public static TEEObject newTEEObjectFromData(Object obj) {

        //Log.e("LUCIA", "PrivateData.add()");
        TEEObject handler = new TEEObject(obj);
        handlers.add(handler);
        return handler;
    }
    
    public static String getStringFromTEEObject(TEEObject teeObj) {
    	return (String)teeObj.getData();
    }
    
    public static byte[] getByteArrayFromTEEObject(TEEObject teeObj) {
    	return (byte[])teeObj.getData();
    }
    
    public static char[] getCharArrayFromTEEObject(TEEObject teeObj) {
    	return (char [])teeObj.getData();
    }
    
    public static SecretKeySpec getSecretKeyFromTEEObject(TEEObject teeObj) {
    	return (SecretKeySpec)teeObj.getData();
    }
    
    public static boolean LockScreenActivity$newEqualsConfirmation(
            TEEObject teeObj1, 
            TEEObject teeObj2) {

        //Log.e("LUCIA", "PrivateData.LockScreenActivity$newEqualsConfirmation");
    	String s1 = getStringFromTEEObject(teeObj1);
    	String s2 = getStringFromTEEObject(teeObj2);
        return s1.equals(s2);
    }

    public static boolean LockScreenActivity$isPasswordFieldEmpty(TEEObject teeObj) {

        //Log.e("LUCIA", "PrivateData.LockScreenActivity$isPasswordFieldEmpty");
        return (getStringFromTEEObject(teeObj)).length() == 0;
    }

    public static TEEObject LockScreenActivity$isPasswordValid(
            TEEObject teeObject) {

        //Log.e("LUCIA", "PrivateData.LockScreenActivity$isPasswordValid");
        char[] tmp = (getStringFromTEEObject(teeObject)).toCharArray();
        TEEObject tmpHandler = newTEEObjectFromData(tmp);
        return tmpHandler;
    }

    public static boolean LockScreenActivity$validatePassword(
            TEEObject teeObj, int minPassLength) {

        //Log.e("LUCIA", "PrivateData.LockScreenActivity$validatePassword");
        char[] pass = getCharArrayFromTEEObject(teeObj);
        return (pass.length < minPassLength && pass.length != 0);
    }

    public static boolean LockScreenActivity$initializeWithPassphrase1(
            TEEObject passphrase) {

        //Log.e("LUCIA", "PrivateData.LockScreenActivity$initializeWithPassphrase1");
        return getStringFromTEEObject(passphrase).isEmpty();
    }

    public static TEEObject LockScreenActivity$initializeWithPassphrase2(
            TEEObject passphrase) {
        //Log.e("LUCIA", "PrivateData.LockScreenActivity$initializeWithPassphrase2");
        char[] tmp = getStringFromTEEObject(passphrase).toCharArray();
        return newTEEObjectFromData(tmp);
    }

    public static boolean LockScreenActivity$isConfirmationFieldEmpty(
            TEEObject mConfirmPassphraseTEE) {
        //Log.e("LUCIA", "PrivateData.LockScreenActivity$isConfirmationFieldEmpty");
        return (getStringFromTEEObject(mConfirmPassphraseTEE)).isEmpty();
    }

    /* TODO: Provide C alternative */
	public static TEEObject PassphraseSecrets$hashPassphrase(
			TEEObject x_password_tee, byte[] salt) throws GeneralSecurityException {
        //Log.e("LUCIA", "PrivateData.PassphraseSecrets$hashPassphrase");

		char[] x_password = getCharArrayFromTEEObject(x_password_tee);
		PBEKeySpec x_spec = null;
        try {
            x_spec                   = new PBEKeySpec(x_password, salt, Constants.PBKDF2_ITER_COUNT, Constants.PBKDF2_KEY_LEN);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            return TEEClient.newTEEObjectFromData(new SecretKeySpec(factory.generateSecret(x_spec).getEncoded(), "AES"));
        } finally {
            Wiper.wipe(x_spec);
        }
	}


    /* TODO: Provide C alternative */
	public static byte[] PassphraseSecrets$decryptSecretKey(
			TEEObject x_passphraseKeyTEE, byte[] iv, byte[] ciphertext) 
					throws GeneralSecurityException {
        //Log.e("LUCIA", "PrivateData.PassphraseSecrets$decryptSecretKey");
		SecretKey x_passphraseKey = getSecretKeyFromTEEObject(x_passphraseKeyTEE);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(ciphertext);
    }


    /* TODO: Provide C alternative */
	public static byte[] PassphraseSecrets$encryptSecretKey(
			TEEObject x_passphraseKeyTEE, byte[] iv, byte[] data) throws GeneralSecurityException {
        //Log.e("LUCIA", "PrivateData.PassphraseSecrets$encryptSecretKey");
		SecretKey x_passphraseKey = (SecretKey) getSecretKeyFromTEEObject(x_passphraseKeyTEE);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // TODO(abel) follow this rabbit hole down and wipe it!
        cipher.init(Cipher.ENCRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(data);
    }
	
	 public static void Wiper$wipeBytes(TEEObject teeObj) {
		 byte[] bytes = getByteArrayFromTEEObject(teeObj);
	     if (bytes == null) return;
	        Arrays.fill(bytes, (byte) 0);
	}
	 
	public static void Wiper$wipeChars(TEEObject teeObj) {
		char[] chars = getCharArrayFromTEEObject(teeObj);
		if(chars == null) return;
        	Arrays.fill(chars, '\0');
    }

	public static void Wiper$wipeSecretKeySpec(TEEObject teeObj) {
        /*for( Field field : SecretKeySpec.class.getDeclaredFields() ) {
        Log.d("Wiper", "SecretKeySpec field: " + field.getName());
    	}*/
		SecretKeySpec key = getSecretKeyFromTEEObject(teeObj);
		if( key == null ) return;
	
	    try {
	        Field key_field = SecretKeySpec.class.getDeclaredField("key");
	        key_field.setAccessible(true);
	        byte[] bytes = (byte[]) key_field.get(key);
	        TEEObject bytesTEE = newTEEObjectFromData(bytes);
	        Wiper$wipeBytes(bytesTEE);
	    } catch (SecurityException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    } catch (NoSuchFieldException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    } catch (IllegalArgumentException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    } catch (IllegalAccessException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    }	
	}
}

