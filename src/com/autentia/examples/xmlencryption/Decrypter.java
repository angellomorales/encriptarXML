package com.autentia.examples.xmlencryption;

import java.io.File;

import java.security.Key;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Este ejemplo desencripta la información encriptada de un documento XML
 * @author Carlos García Pérez. Autentia.
 * @see    http://www.mobiletest.es
 */
public class Decrypter {
	private static final String SECRET_KEY_FILENAME 	  = "mykey.dat";
	private static final String	ENCRYPTED_XML_FILENAME    = "infoCifrada.xml";
	private static final String	DESENCRYPTED_XML_FILENAME = "infoDescifrada.xml";
	

    /**
     * @return La clave de encriptación/encriptación desde un archivo
     * @throws Exception Cualquier incidencia
     */
    private static SecretKey loadDesencryptionKey() throws Exception {
        DESedeKeySpec	 keySpec = new DESedeKeySpec(JavaUtils.getBytesFromFile(SECRET_KEY_FILENAME));
        SecretKeyFactory skf	 = SecretKeyFactory.getInstance("DESede");
        SecretKey		 key	 = skf.generateSecret(keySpec);
        
        return key;
    }

    /**
     * Punto de entrada del ejemplo
     * @throws Exception Cualquier incidencia
     */
    public static void desencriptar() throws Exception {
    	 // Inicializamos el FrameWork de seguridad de Apache a los valores por defecto 
    	org.apache.xml.security.Init.init();
    	
    	// Obtenemos el documento xml encriptado
        Document document = DOMUtils.loadDocumentFromFile(new File(ENCRYPTED_XML_FILENAME));
        
        // Accedemos al nodo con la información encriptada.		 namespace: "http://www.w3.org/2001/04/xmlenc#", localName: "EncryptedData"
        Element	node = (Element) document.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
        Key		kek	 = Decrypter.loadDesencryptionKey();	// Carga la clave para desencriptar la información
        
        // La clave que será usada para desencriptar los datos del xml se obtendrá desde el KeyInfo del EncrypteData usando la EncryptedKey  
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, null);	// Key=null para que use como clave el EncryptedKey 
        cipher.setKEK(kek);		
        
        // Desencriptamos reemplazando los datos encriptados con su contenido desencriptado
        cipher.doFinal(document, node);

        // Guarda el Document en un archivo
        File file = new File(DESENCRYPTED_XML_FILENAME);
        DOMUtils.outputDocToFile(document, file);
        
        System.out.println("Los datos han sido desencriptados en: " + file.toURL().toString());
    }
}