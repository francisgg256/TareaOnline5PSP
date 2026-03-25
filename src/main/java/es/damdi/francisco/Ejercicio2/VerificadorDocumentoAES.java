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
        // 1. Comprobamos los 4 parámetros de línea de comandos
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
            // Comprobamos si el archivo cifrado existe
            File fileIn = new File(ficheroCifrado);
            if (!fileIn.exists()) {
                System.err.println("Error: El fichero cifrado '" + ficheroCifrado + "' no existe.");
                return;
            }

            // 2. Recuperar la clave simétrica almacenada
            byte[] claveBytes = leerDeFichero(ficheroClave);
            // Reconstruimos la clave AES a partir de sus bytes
            SecretKeySpec claveSimetrica = new SecretKeySpec(claveBytes, "AES");
            System.out.println("Clave AES recuperada correctamente.");

            // 3. Recuperar el hash original
            byte[] hashOriginal = leerDeFichero(ficheroHash);
            System.out.println("Hash original recuperado.");

            // 4. Preparar el cifrador en modo DESCIFRADO y el MessageDigest para el nuevo Hash
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, claveSimetrica);
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            System.out.println("Descifrando el documento y calculando el nuevo hash...");

            // 5. Descifrar el fichero mediante flujos de datos (CipherInputStream)
            // A la vez que leemos el flujo descifrado, vamos calculando el nuevo hash y guardando en el nuevo fichero
            try (FileInputStream fis = new FileInputStream(ficheroCifrado);
                 CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(ficheroDescifrado)) {

                byte[] buffer = new byte[1024];
                int bytesLeidos;

                while ((bytesLeidos = cis.read(buffer)) != -1) {
                    // Escribimos el contenido descifrado en el nuevo archivo
                    fos.write(buffer, 0, bytesLeidos);
                    // Actualizamos el nuevo hash con los datos descifrados
                    md.update(buffer, 0, bytesLeidos);
                }
            }

            // Obtenemos el hash del archivo que acabamos de descifrar
            byte[] hashCalculado = md.digest();
            System.out.println("Documento descifrado guardado en: " + ficheroDescifrado);

            // 6. Verificación de integridad: Comparamos ambos hashes
            System.out.println("\n--- RESULTADO DE LA VERIFICACIÓN DE INTEGRIDAD ---");
            if (MessageDigest.isEqual(hashOriginal, hashCalculado)) {
                System.out.println("✅ INTEGRIDAD CONFIRMADA.");
                System.out.println("Los resúmenes coinciden. El fichero no ha sido modificado.");
            } else {
                System.out.println("❌ INTEGRIDAD COMPROMETIDA.");
                System.out.println("Los resúmenes NO coinciden. El fichero ha sido alterado.");
            }

        } catch (Exception e) {
            System.err.println("Ocurrió un error en el proceso de descifrado o verificación: ");
            e.printStackTrace();
        }
    }

    /**
     * Método auxiliar para leer todos los bytes de un fichero y manejar si no existe.
     */
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
