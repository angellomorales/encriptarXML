package com.autentia.examples.xmlencryption;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Clase de utilidad.
 * @author Carlos García Pérez. Autentia.
 * @see     http://www.mobiletest.es
 */
public class DOMUtils {
	
    /**
     * Serializa un objeto Document en un archivo
     */
    public static void outputDocToFile(Document doc, File file) throws Exception {
        FileOutputStream f = new FileOutputStream(file);
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer	= factory.newTransformer();
        
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        
        transformer.transform(new DOMSource(doc), new StreamResult(f));

        f.close();
    }
    
    /**
     * Lee un Document desde un archivo
     */
    public static Document loadDocumentFromFile(java.io.File file) throws Exception {
        DocumentBuilderFactory	factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder	builder = null;
        
        factory.setNamespaceAware(true);
        
        builder = factory.newDocumentBuilder();
        
        return builder.parse(file);
    } 
    
	/**
	 * @return Crea un elemento <tag>value</tag>
	 */
	public static Element createNode(Document document, String tag, String value){
        Element node = document.createElement(tag);
        if (value != null){
        	node.appendChild(document.createTextNode(value));
        }
		return node;
	}    
}