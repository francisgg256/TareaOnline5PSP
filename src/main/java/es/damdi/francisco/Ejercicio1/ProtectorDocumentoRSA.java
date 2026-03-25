package es.damdi.francisco.Ejercicio1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;

public class ProtectorDocumentoRSA {

    public static void main(String[] args) {
        if (args.length < 5) {
            System.out.println("Error de sintaxis. Uso correcto:");
            System.out.println("java ProtectorDocumentoRSA <fichero_entrada> <fichero_cifrado_salida> <clave_publica_salida> <clave_privada_salida> <firma_salida>");
            return;
        }

        String ficheroEntrada = args[0];
        String ficheroCifrado = args[1];
        String ficheroClavePublica = args[2];
        String ficheroClavePrivada = args[3];
        String ficheroFirma = args[4];

        try {
            File fileIn = new File(ficheroEntrada);
            if (!fileIn.exists()) {
                System.err.println("Error: El fichero de entrada '" + ficheroEntrada + "' no existe.");
                return;
            }

            System.out.println("Generando par de claves RSA...");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair claves = keyGen.generateKeyPair();

            PrivateKey clavePrivada = claves.getPrivate();
            PublicKey clavePublica = claves.getPublic();

            guardarEnFichero(ficheroClavePublica, clavePublica.getEncoded());
            guardarEnFichero(ficheroClavePrivada, clavePrivada.getEncoded());
            System.out.println("Claves guardadas correctamente.");

            byte[] contenidoOriginal = leerDeFichero(ficheroEntrada);

            System.out.println("Generando firma digital...");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(clavePrivada);
            signature.update(contenidoOriginal);
            byte[] firmaBytes = signature.sign();

            guardarEnFichero(ficheroFirma, firmaBytes);
            System.out.println("Firma guardada en: " + ficheroFirma);

            System.out.println("Cifrando el documento...");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
            byte[] contenidoCifrado = cipher.doFinal(contenidoOriginal);

            guardarEnFichero(ficheroCifrado, contenidoCifrado);
            System.out.println("Documento cifrado guardado en: " + ficheroCifrado);

            System.out.println("\n¡Proceso de la Parte 1 completado con éxito!");

        } catch (Exception e) {
            System.err.println("Ocurrió un error inesperado durante el proceso criptográfico.");
            e.printStackTrace();
        }
    }

    private static byte[] leerDeFichero(String ruta) throws IOException {
        try (FileInputStream fis = new FileInputStream(ruta)) {
            return fis.readAllBytes();
        }
    }

    private static void guardarEnFichero(String ruta, byte[] contenido) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(ruta)) {
            fos.write(contenido);
        }
    }
}
