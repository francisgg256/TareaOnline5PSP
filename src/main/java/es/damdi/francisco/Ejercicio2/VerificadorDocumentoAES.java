package es.damdi.francisco.Ejercicio2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;

public class VerificadorDocumentoAES {

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Error de sintaxis. Uso correcto:");
            System.out.println("java VerificadorDocumentoAES <fichero_cifrado> <fichero_clave> <fichero_hash_original> <fichero_descifrado_salida>");
            return;
        }

        String ficheroCifrado = args[0];
        String ficheroClave = args[1];
        String ficheroHash = args[2];
        String ficheroDescifrado = args[3];

        try {
            File fileIn = new File(ficheroCifrado);
            if (!fileIn.exists()) {
                System.err.println("Error: El fichero cifrado '" + ficheroCifrado + "' no existe.");
                return;
            }

            byte[] claveBytes = leerDeFichero(ficheroClave);
            SecretKeySpec claveSimetrica = new SecretKeySpec(claveBytes, "AES");
            System.out.println("Clave AES recuperada correctamente.");

            byte[] hashOriginal = leerDeFichero(ficheroHash);
            System.out.println("Hash original recuperado.");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, claveSimetrica);
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            System.out.println("Descifrando el documento y calculando el nuevo hash...");

            try (FileInputStream fis = new FileInputStream(ficheroCifrado);
                 CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(ficheroDescifrado)) {

                byte[] buffer = new byte[1024];
                int bytesLeidos;

                while ((bytesLeidos = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesLeidos);
                    md.update(buffer, 0, bytesLeidos);
                }
            }

            byte[] hashCalculado = md.digest();
            System.out.println("Documento descifrado guardado en: " + ficheroDescifrado);

            System.out.println("\n--- RESULTADO DE LA VERIFICACIÓN DE INTEGRIDAD ---");
            if (MessageDigest.isEqual(hashOriginal, hashCalculado)) {
                System.out.println("INTEGRIDAD CONFIRMADA.");
                System.out.println("Los resúmenes coinciden. El fichero no ha sido modificado.");
            } else {
                System.out.println("INTEGRIDAD COMPROMETIDA.");
                System.out.println("Los resúmenes NO coinciden. El fichero ha sido alterado.");
            }

        } catch (Exception e) {
            System.err.println("Ocurrió un error en el proceso de descifrado o verificación: ");
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
