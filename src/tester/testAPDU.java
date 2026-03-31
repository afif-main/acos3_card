package tester;

import com.app.Myapplet;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

public class testAPDU {

    // Codes de sécurité par défaut
    private static final byte[] IC_CODE = {0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54}; // "ACOSTEST"
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    private static final byte[] NEW_PIN = {0x09, 0x09, 0x09, 0x09};

    public static void main(String[] args) {
        System.out.println("=== DEMARRAGE DU SIMULATEUR JCARDSIM ===");
        Simulator simulator = new Simulator();
        AID appletAID = AIDUtil.create(new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x01});
        simulator.installApplet(appletAID, Myapplet.class);
        simulator.selectApplet(appletAID);
        System.out.println(">>> Applet installée et sélectionnée.\n");

        try {
            // =========================================================================
            // PARTIE 1 : SESSION ADMINISTRATEUR (Accès avec IC Code)
            // But : Créer un fichier utilisateur et y inscrire le profil
            // =========================================================================
            System.out.println("--- PARTIE 1 : CREATION DU PROFIL (IC CODE) ---");

            // 1. Soumettre le code IC
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0x20, 0x07, 0x00, IC_CODE)), "Validation IC Code");

            // 2. Définir le nombre de fichiers (N_OF_FILE = 1) dans FF02
            transmit(simulator, new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xFF, 0x02}));
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0xD2, 0x00, 0x00, new byte[]{0x00, 0x00, 0x01, 0x00})), "Allocation (FF02)");

            // 3. Définir le fichier A0A0 dans FF04 (User File Management)
            // [0]=Taille(32), [1]=NbRecords(1), [2]=ReadAC(01=PIN), [3]=WriteAC(00=Libre), [4-5]=ID(A0A0)
            transmit(simulator, new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xFF, 0x04}));
            byte[] fileDef = {0x20, 0x01, 0x01, 0x00, (byte)0xA0, (byte)0xA0};
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0xD2, 0x00, 0x00, fileDef)), "Définition Fichier A0A0 (FF04)");

            // 4. Ecrire les données du profil dans A0A0
            transmit(simulator, new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xA0, (byte)0xA0}));
            String profil = "Axel, Etudiant, 2026, 25 ans";
            byte[] profilBytes = Arrays.copyOf(profil.getBytes(), 32); // Remplissage avec des 0 pour faire 32 octets
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0xD2, 0x00, 0x00, profilBytes)), "Ecriture du profil dans A0A0");

            
            // =========================================================================
            // PARTIE 2 : SESSION UTILISATEUR (Accès avec PIN)
            // But : Lire le profil, vérifier solde, crédit, débit, changer PIN
            // =========================================================================
            System.out.println("\n--- PARTIE 2 : UTILISATION & TRANSACTIONS (PIN CODE) ---");
            
            // On simule le retrait et la réinsertion de la carte
            simulator.reset();
            simulator.selectApplet(appletAID);
            System.out.println(">>> Carte réinsérée (Nouvelle session).");

            // 1. Authentification 3DES (Requise par ton applet pour accéder au solde EE01)
            authenticate(simulator, new byte[16]);

            // 2. Soumettre le code PIN
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0x20, 0x06, 0x00, DEFAULT_PIN)), "Validation Code PIN");

            // 3. Lire le profil dans A0A0
            transmit(simulator, new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xA0, (byte)0xA0}));
            ResponseAPDU rp = transmit(simulator, new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x20));
            checkStatus(rp, "Lecture du profil");
            System.out.println("    => PROFIL LU : " + new String(rp.getData()).trim());

            // 4. Sélectionner le fichier Balance (EE01)
            transmit(simulator, new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xEE, 0x01}));

            // 5. Lire le solde initial
            rp = transmit(simulator, new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x02));
            int solde = ((rp.getData()[0] & 0xFF) << 8) | (rp.getData()[1] & 0xFF);
            System.out.println("    => Solde actuel : " + solde + " Unités");

            // 6. CREDIT de +500 unités (0x01F4)
            // [4 octets MAC vides] + [3 octets Montant] + [4 octets TTREF]
            byte[] creditData = {0x00, 0x00, 0x00, 0x00,  0x00, 0x01, (byte)0xF4,  0x00, 0x00, 0x00, 0x00};
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0xE2, 0x00, 0x00, creditData)), "CREDIT de 500");

            // 7. Vérifier le nouveau solde
            rp = transmit(simulator, new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x02));
            solde = ((rp.getData()[0] & 0xFF) << 8) | (rp.getData()[1] & 0xFF);
            System.out.println("    => Nouveau Solde : " + solde + " Unités");

            // 8. DEBIT de -200 unités (0x00C8)
            byte[] debitData = {0x00, 0x00, 0x00, 0x00,  0x00, 0x00, (byte)0xC8,  0x00, 0x00, 0x00, 0x00};
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0xE6, 0x00, 0x00, debitData)), "DEBIT de 200");

            // 9. Vérifier le solde final
            rp = transmit(simulator, new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x02));
            solde = ((rp.getData()[0] & 0xFF) << 8) | (rp.getData()[1] & 0xFF);
            System.out.println("    => Solde Final : " + solde + " Unités");

            // 10. Changer le code PIN
            checkStatus(transmit(simulator, new CommandAPDU(0x80, 0x24, 0x00, 0x00, NEW_PIN)), "Changement du code PIN (Nouveau: 9999)");

            System.out.println("\n=== TESTS TERMINES AVEC SUCCES ===");

        } catch (Exception e) {
            System.err.println("\n[X] Erreur : " + e.getMessage());
        }
    }

    // --- METHODES UTILITAIRES ---

    private static ResponseAPDU transmit(Simulator simulator, CommandAPDU cmd) {
        return new ResponseAPDU(simulator.transmitCommand(cmd.getBytes()));
    }

    private static void checkStatus(ResponseAPDU rp, String etape) throws Exception {
        if (rp.getSW() != 0x9000 && rp.getSW1() != 0x91) {
            throw new Exception("Echec [" + etape + "] : SW=" + Integer.toHexString(rp.getSW()).toUpperCase());
        } else {
            System.out.println("OK : " + etape + " (SW=" + Integer.toHexString(rp.getSW()).toUpperCase() + ")");
        }
    }

    private static void authenticate(Simulator simulator, byte[] key16) throws Exception {
        // Obtenir le challenge
        ResponseAPDU rp = transmit(simulator, new CommandAPDU(0x80, 0x84, 0x00, 0x00, 0x08));
        if (rp.getSW() != 0x9000) throw new Exception("Echec Get Challenge");
        
        // Calcul 3DES
        byte[] challenge = rp.getData();
        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8); // Copie pour faire 24 octets (clé 3DES Java)
        
        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key24, "DESede"));
        byte[] cryptogram = cipher.doFinal(challenge);

        // Envoyer la réponse
        checkStatus(transmit(simulator, new CommandAPDU(0x80, 0x82, 0x00, 0x00, cryptogram)), "Authentification 3DES Terminal");
    }
}