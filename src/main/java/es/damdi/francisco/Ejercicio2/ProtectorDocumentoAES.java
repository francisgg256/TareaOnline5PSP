package es.damdi.francisco.Ejercicio2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ProtectorDocumentoAES {

    public static void main(String[] args) {
        // 1. Comprobamos los 4 parámetros de línea de comandos
        if (args.length < 4) {
            System.out.println("Error de sintaxis. Uso correcto:");
            System.out.println("java ProtectorDocumentoAES <fichero_entrada> <fichero_cifrado_salida> <clave_simetrica_salida> <hash_salida>");
            return;
        }

        String ficheroEntrada = args[0];
        String ficheroCifrado = args[1];
        String ficheroClave = args[2];
        String ficheroHash = args[3];

        try {
            // Comprobamos si el archivo original existe
            File fileIn = new File(ficheroEntrada);
            if (!fileIn.exists()) {
                System.err.println("Error: El fichero de entrada '" + ficheroEntrada + "' no existe.");
                return;
            }

            // 2. Generar clave simétrica AES
            System.out.println("Generando clave simétrica AES...");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // Tamaño de clave recomendado para AES (128 o 256 bits)
            SecretKey claveSimetrica = keyGen.generateKey();

            // Guardamos la clave simétrica en un fichero binario
            try (FileOutputStream fosClave = new FileOutputStream(ficheroClave)) {
                fosClave.write(claveSimetrica.getEncoded());
            }
            System.out.println("Clave AES guardada en: " + ficheroClave);

            // 3. Calcular el hash (SHA-256) del fichero original
            System.out.println("Calculando el hash del archivo original...");
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Leemos por fragmentos (buffer) para no saturar la memoria si el archivo es muy grande
            try (FileInputStream fisHash = new FileInputStream(ficheroEntrada)) {
                byte[] buffer = new byte[1024];
                int bytesLeidos;
                while ((bytesLeidos = fisHash.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesLeidos);
                }
            }
            byte[] hashOriginal = md.digest();

            // Guardamos el hash en su fichero
            try (FileOutputStream fosHash = new FileOutputStream(ficheroHash)) {
                fosHash.write(hashOriginal);
            }
            System.out.println("Hash original guardado en: " + ficheroHash);

            // 4. Cifrar el fichero mediante flujos de datos (CipherOutputStream)
            System.out.println("Cifrando el documento mediante CipherOutputStream...");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, claveSimetrica);

            // Usamos CipherOutputStream para ir cifrando conforme leemos y escribimos
            try (FileInputStream fisCifrado = new FileInputStream(ficheroEntrada);
                 FileOutputStream fosCifrado = new FileOutputStream(ficheroCifrado);
                 CipherOutputStream cos = new CipherOutputStream(fosCifrado, cipher)) {

                byte[] buffer = new byte[1024];
                int bytesLeidos;
                while ((bytesLeidos = fisCifrado.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesLeidos);
                }
            }
            System.out.println("Documento cifrado guardado en: " + ficheroCifrado);

            System.out.println("\n¡Proceso de la Parte 1 (AES) completado con éxito!");

        } catch (Exception e) {
            System.err.println("Ocurrió un error en el proceso criptográfico: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
