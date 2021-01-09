package com.autentia.examples.xmlencryption;


import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import javax.xml.parsers.*;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Este ejemplo encripta la información relacionada con la tarjeta de crédito de un cliente
 * @author Carlos García Pérez. Autentia.
 * @see     http://www.mobiletest.es 
 */
public class Encrypter {
	private static final String SECRET_KEY_FILENAME = "mykey.dat";
	private static final String ENCRYPTED_XML_FILENAME    = "infoCifrada.xml";
	
    /**
     * Genera un Document de ejemplo
     */    
    public static Document createSampleDom() throws Exception {
    	DocumentBuilderFactory	factory  = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder	 = factory.newDocumentBuilder();
        Document document = builder.newDocument();
        
        Element person = document.createElement("persona");
        person.setAttribute("id", "468300000");
        
        person.appendChild(DOMUtils.createNode(document, "nombre",	 "Marvis"));
        person.appendChild(DOMUtils.createNode(document, "apellidos", "Rondon Marcelo"));
        person.appendChild(DOMUtils.createNode(document, "email",	    "marvis@servidor.com"));
        
        Element creditCard = document.createElement("tarjetaCredito");
        creditCard.appendChild(DOMUtils.createNode(document, "numero",	 "83838383"));
        creditCard.appendChild(DOMUtils.createNode(document, "fechaExpiracion",	 "01/05"));
        
        person.appendChild(creditCard);
        
        document.appendChild(person);
        

        return document;
    }

    
    /**
     * @return Genera la clave secreta que servirá para encriptar/desencriptar la información 
     * @throws Exception Cualquier incidencia
     */
    public static SecretKey generateAndStoreKeyEncryptionKey() throws Exception {
        // Generamos la clave usando el algoritmo Triple DES
    	KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");	// Algoritmo JCE: Triple DES
        SecretKey secret = keyGenerator.generateKey();
        byte[] bytes = secret.getEncoded();
        
        // Guardamos la clave en disco
        File keyFile = new File(SECRET_KEY_FILENAME);
        FileOutputStream output	 = new FileOutputStream(keyFile);
        output.write(bytes);
        output.close();
        
        System.out.println("La clave de encriptación está guardada en: " + keyFile.getAbsolutePath());

        return secret;
    }

    /**
     * @return Devuelve la clave de encriptación de datos
     * @throws Exception Cualquier incidencia
     */    
    public static SecretKey generateDataEncryptionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");	// Algoritmo JCE: Advanced Encryption Standard
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }


    /**
     * Punto de entrada del ejemplo
     * @throws Exception Cualquier incidencia
     */
    public static void encriptar() throws Exception {
    	// Inicializamos el FrameWork de seguridad de Apache a los valores por defecto 
    	org.apache.xml.security.Init.init();
    	 
        Document document = Encrypter.createSampleDom();

        // Obtenemos la clave para encriptar el elemento.
        Key symmetricKey = Encrypter.generateDataEncryptionKey();

        // Obtenemos la clave para encriptar la clave simétrica
        Key kek = Encrypter.generateAndStoreKeyEncryptionKey();
        
        // Inicializa cifrador para cifrar la clave de cifrado de la información del documento  xml
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);	// URI "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
        keyCipher.init(XMLCipher.WRAP_MODE, kek);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);	 // Ciframos la clave simétrica

		// Cifrar el contenido del elemento
        XMLCipher	xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);	// URI "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
        
        // Añadimos información sobre la clave de cifrado. KeyInfo
        EncryptedData encryptedData = xmlCipher.getEncryptedData(); 
        KeyInfo	keyInfo	= new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        /*
         * Criframos!!
         * Reemplazamos en el documento los datos a encriptar por el elemento EncrypteData
         * con el tercer parámetro a true indica que deseamos encriptar el contenido del elemento 
         * y no el elemento en sí.
         */
        Element	node = (Element) document.getElementsByTagName("tarjetaCredito").item(0);
        
        xmlCipher.doFinal(document, node, false);

        // Guarda el Document en un archivo
        File file = new File(ENCRYPTED_XML_FILENAME);
        DOMUtils.outputDocToFile(document, file);
        
        System.out.println("Los datos han sido encriptados en: " + file.toURL().toString());        
    }
}