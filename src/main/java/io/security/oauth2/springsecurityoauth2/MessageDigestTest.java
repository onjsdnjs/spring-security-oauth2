package io.security.oauth2.springsecurityoauth2;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class MessageDigestTest {

    public static void createMD5(String message) throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[10];
        random.nextBytes(salt);

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(salt);
        messageDigest.update(message.getBytes("UTF-8"));

        byte[] digest = messageDigest.digest();

        FileOutputStream fileOutputStream = new FileOutputStream("c:\\message.txt");
        fileOutputStream.write(salt);
        fileOutputStream.write(digest);
        fileOutputStream.close();
    }

    public static void validateMD5(String message) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream("c:\\message.txt");
        int theByte = 0;
        while ((theByte = fis.read()) != -1)
            byteArrayOutputStream.write(theByte);
        fis.close();
        byte[] hashedMessage = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.reset();

        byte[] salt = new byte[10];
        System.arraycopy(hashedMessage, 0, salt, 0, 10);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(salt);
        md.update(message.getBytes("UTF-8"));
        byte[] digest = md.digest();

        byte[] digestInFile = new byte[hashedMessage.length - 10];
        System.arraycopy(hashedMessage, 12, digestInFile, 0, hashedMessage.length - 10);

        if (Arrays.equals(digest, digestInFile))
            System.out.println("message matches.");
        else
            System.out.println("message does not matches.");
    }
}
