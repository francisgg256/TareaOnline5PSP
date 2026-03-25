package es.damdi.francisco.Ejercicio1;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class VerificadorDocumentoRSA {

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Error de sintaxis. Uso correcto:");
            System.out.println("java VerificadorDocumentoRSA <fichero_cifrado> <clave_publica> <clave_privada> <fichero_firma>");
            return;
        }

        String ficheroCifrado = args[0];
        String ficheroClavePublica = args[1];
        String ficheroClavePrivada = args[2];
        String ficheroFirma = args[3];

        try {
            byte[] contenidoCifrado = leerDeFichero(ficheroCifrado);
            byte[] pubKeyBytes = leerDeFichero(ficheroClavePublica);
            byte[] privKeyBytes = leerDeFichero(ficheroClavePrivada);
            byte[] firmaBytes = leerDeFichero(ficheroFirma);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
            PublicKey clavePublica = keyFactory.generatePublic(pubSpec);

            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            PrivateKey clavePrivada = keyFactory.generatePrivate(privSpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
            byte[] contenidoDescifrado = cipher.doFinal(contenidoCifrado);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(clavePublica);
            signature.update(contenidoDescifrado);

            boolean firmaValida = signature.verify(firmaBytes);

            System.out.println("--- RESULTADO DE LA VERIFICACIÓN ---");
            if (firmaValida) {
                System.out.println("FIRMA VÁLIDA.");
                System.out.println("-> Autenticación: El documento fue firmado por el emisor legítimo.");
                System.out.println("-> Integridad: El contenido no ha sido modificado.\n");

                System.out.println("Contenido del documento original:");
                System.out.println(new String(contenidoDescifrado));
            } else {
                System.out.println("FIRMA NO VÁLIDA.");
                System.out.println("El documento ha sido alterado o no pertenece al emisor legítimo.");
            }

        } catch (Exception e) {
            System.err.println("Ocurrió un error leyendo los ficheros o en el proceso criptográfico.");
            e.printStackTrace();
        }
    }

    private static byte[] leerDeFichero(String ruta) throws IOException {
        File archivo = new File(ruta);
        if (!archivo.exists()) {
            throw new IOException("No se encuentra el archivo: " + ruta);
        }
        try (FileInputStream fis = new FileInputStream(archivo)) {
            return fis.readAllBytes();
        }
    }
}
