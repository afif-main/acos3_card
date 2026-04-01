package tester;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.util.Arrays;
import java.util.List;

public class testAPDU {

    // Default ACOS3 Codes
    private static final byte[] IC_CODE = {0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54}; // "ACOSTEST"
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    private static final byte[] NEW_PIN = {0x09, 0x09, 0x09, 0x09};
    private static final byte[] APPLET_AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x02};

    // Default Card Key for 3DES Authentication (Zeroes in the Applet)
    private static final byte[] CARD_KEY = new byte[16];

    public static void main(String[] args) {
        System.out.println("=== STARTING TERMINAL TEST FOR ACOS3 ===");

        try {
            // =========================================================================
            // 0. CONNECTION & SELECTION
            // =========================================================================
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            if (terminals.isEmpty()) {
                throw new Exception("No card reader found! Please check your USB connection.");
            }
            
            CardTerminal terminal = terminals.get(0);
            System.out.println(">>> Connecting to: " + terminal.getName());
            
            // Connect to the card (using "*" for any available protocol T=0 or T=1)
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            System.out.println(">>> Card connected. Protocol: " + card.getProtocol());

            // Select the Applet
            CommandAPDU selectCmd = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID);
            checkStatus(channel.transmit(selectCmd), "Select Applet");


            // =========================================================================
            // PHASE 1: ADMIN & PERSONALIZATION
            // =========================================================================
            System.out.println("\n--- PHASE 1: PERSONALIZATION (IC CODE) ---");

            // 1. Submit IC Code
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x20, 0x07, 0x00, IC_CODE)), "Submit IC Code");
            
            // 2. Define the number of files (N_OF_FILE = 1) in FF02
            channel.transmit(new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xFF, 0x02}));
            byte[] mcuConfig = {0x00, 0x00, 0x01, 0x00}; 
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xD2, 0x00, 0x00, mcuConfig)), "Write N_OF_FILE=1 to FF02 (MCU)");

            // 3. Define a User File A0A0 in FF04
            channel.transmit(new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xFF, 0x04}));
            byte[] fileDef = {0x20, 0x01, 0x42, (byte)0x80, (byte)0xA0, (byte)0xA0};
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xD2, 0x00, 0x00, fileDef)), "Define User File A0A0 in FF04");

            // 4. Write data to User File A0A0
            channel.transmit(new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xA0, (byte)0xA0}));
            String profile = "Axel, JavaCard Dev, 2026";
            byte[] profileBytes = Arrays.copyOf(profile.getBytes(), 32); 
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xD2, 0x00, 0x00, profileBytes)), "Write Data to A0A0");


            // =========================================================================
            // PHASE 2: USER TRANSACTIONS & PURSE OPERATIONS
            // =========================================================================
            System.out.println("\n--- PHASE 2: USER TRANSACTIONS (3DES + PIN) ---");
            
            // Re-selecting the applet acts as a session reset, clearing previous IC Code auth
            System.out.println(">>> Re-selecting applet to clear session state...");
            checkStatus(channel.transmit(selectCmd), "Select Applet (Session Reset)");

            // 1. 3DES Mutual Authentication
            authenticate(channel, CARD_KEY);

            // 2. Submit PIN Code
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x20, 0x06, 0x00, DEFAULT_PIN)), "Submit PIN Code");

            // 3. Read Profile from A0A0
            channel.transmit(new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xA0, (byte)0xA0}));
            ResponseAPDU rp = channel.transmit(new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x20));
            checkStatus(rp, "Read A0A0");
            System.out.println("    => DATA: " + new String(rp.getData()).trim());

            // 4. Select Account File (FF05)
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xA4, 0x00, 0x00, new byte[]{(byte)0xFF, 0x05})), "Select FF05 (Account File)");

            // 5. Inquire Account (E4)
            byte[] dummyRef = {0x00, 0x00, 0x00, 0x00};
            rp = channel.transmit(new CommandAPDU(0x80, 0xE4, 0x00, 0x00, dummyRef));
            checkStatus(rp, "Inquire Account (INS E4)");

            // 6. Read Initial Balance (FF05, Record 0)
            rp = channel.transmit(new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x04));
            int balance = ((rp.getData()[2] & 0xFF) << 8) | (rp.getData()[3] & 0xFF);
            System.out.println("    => Initial Balance : " + balance + " Units");

            // 7. CREDIT 500 Units (INS E2)
         
            byte[] creditPayload = {(byte)0x00, (byte)0x01, (byte)0xF4, 0x0A, 0x0B, 0x0C, 0x0D};
            byte[] creditMac = generateMac(CARD_KEY, creditPayload);
            byte[] creditData = new byte[11];
            System.arraycopy(creditMac, 0, creditData, 0, 4);     // Insert 4-byte MAC
            System.arraycopy(creditPayload, 0, creditData, 4, 7); // Insert Payload
            
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xE2, 0x00, 0x00, creditData)), "CREDIT 500");
            
            rp = channel.transmit(new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x04));
            balance = ((rp.getData()[2] & 0xFF) << 8) | (rp.getData()[3] & 0xFF);
            System.out.println("    => Balance after Credit : " + balance + " Units");

            // 8. DEBIT 200 Units  (0x00C8) (INS E6)
            byte[] debitPayload = {(byte)0x00, (byte)0x00, (byte)0xC8, 0x01, 0x02, 0x03, 0x04};
            byte[] debitMac = generateMac(CARD_KEY, debitPayload);
            byte[] debitData = new byte[11];
            System.arraycopy(debitMac, 0, debitData, 0, 4);     // Insert 4-byte MAC
            System.arraycopy(debitPayload, 0, debitData, 4, 7); // Insert Payload
            
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xE6, 0x00, 0x00, debitData)), "DEBIT 200");

            rp = channel.transmit(new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x04));
            balance = ((rp.getData()[2] & 0xFF) << 8) | (rp.getData()[3] & 0xFF);
            System.out.println("    => Balance after Debit  : " + balance + " Units");

            // 9. REVOKE DEBIT (INS E8)
            byte[] revokePayload = new byte[0]; 
            byte[] revokeMac = generateMac(CARD_KEY, revokePayload);
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0xE8, 0x00, 0x00, revokeMac)), "REVOKE DEBIT");

            rp = channel.transmit(new CommandAPDU(0x80, 0xB2, 0x00, 0x00, 0x04));
            balance = ((rp.getData()[2] & 0xFF) << 8) | (rp.getData()[3] & 0xFF);
            System.out.println("    => Balance after Revoke : " + balance + " Units (Restored!)");
            
            // =========================================================================
            // PHASE 3: SECURITY & CLEANUP
            // =========================================================================
            System.out.println("\n--- PHASE 3: SECURITY & CLEANUP ---");

            // 1. Change PIN Code 
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x24, 0x00, 0x00, NEW_PIN)), "Change PIN to 09 09 09 09");

            // 2. Re-Authenticate as Issuer
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x20, 0x07, 0x00, IC_CODE)), "Submit IC Code (Admin Login)");

            // 3. Clear Card (INS 30)
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x30, 0x00, 0x00, 0x00)), "Clear Card");

            // 4. Verify PIN reset
            checkStatus(channel.transmit(new CommandAPDU(0x80, 0x20, 0x06, 0x00, DEFAULT_PIN)), "Verify PIN reset to defaults");

            // Disconnect reader
            card.disconnect(false);
            System.out.println("\n=== ALL ACOS3 TESTS PASSED ON PHYSICAL TERMINAL ===");

        } catch (Exception e) {
            System.err.println("\n[X] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // --- UTILITIES ---

    private static void checkStatus(ResponseAPDU rp, String step) throws Exception {
        if (rp.getSW() != 0x9000 && rp.getSW1() != 0x91) {
            throw new Exception("Failed [" + step + "] : SW=" + Integer.toHexString(rp.getSW()).toUpperCase());
        } else {
            System.out.println("[OK] " + step + " (SW=" + Integer.toHexString(rp.getSW()).toUpperCase() + ")");
        }
    }

    private static void authenticate(CardChannel channel, byte[] key16) throws Exception {
        // 1. Get Challenge (INS 84)
        ResponseAPDU rp = channel.transmit(new CommandAPDU(0x80, 0x84, 0x00, 0x00, 0x08));
        if (rp.getSW() != 0x9000) throw new Exception("Get Challenge Failed");
        
        byte[] challenge = rp.getData();
        
        // 2. Prepare 24-byte key for Java's DESede
        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8); 
        
        // 3. Encrypt challenge
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        byte[] zeroIv = new byte[8];
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key24, "DESede"), new IvParameterSpec(zeroIv));
        byte[] cryptogram = cipher.doFinal(challenge);

        // 4. Send Authenticate command (INS 82)
        checkStatus(channel.transmit(new CommandAPDU(0x80, 0x82, 0x00, 0x00, cryptogram)), "3DES CBC Mutual Authentication");
    }
    private static byte[] generateMac(byte[] key16, byte[] payload) throws Exception {
        // 1. Apply ISO9797 Method 2 Padding (append 0x80, then pad with zeroes to a multiple of 8)
        int paddedLen = (payload.length / 8 + 1) * 8;
        byte[] padded = new byte[paddedLen];
        System.arraycopy(payload, 0, padded, 0, payload.length);
        padded[payload.length] = (byte) 0x80;

        // 2. Prepare 24-byte key for Java's DESede (Copy first 8 bytes to the end)
        byte[] key24 = new byte[24];
        System.arraycopy(key16, 0, key24, 0, 16);
        System.arraycopy(key16, 0, key24, 16, 8);

        // 3. Encrypt the padded data using 3DES CBC with a Zero IV
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key24, "DESede"), new IvParameterSpec(new byte[8]));
        byte[] encrypted = cipher.doFinal(padded);

        // 4. The MAC is the last 8-byte encrypted block. ACOS3 checks the first 4 bytes of this block.
        byte[] mac = new byte[4];
        System.arraycopy(encrypted, encrypted.length - 8, mac, 0, 4);
        
        return mac;
    }    
}