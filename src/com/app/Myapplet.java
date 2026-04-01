package com.app;

import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.KeyBuilder;
import javacard.security.DESKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class Myapplet extends Applet {
    
    private boolean sessionActive = false;
    private boolean isMutualAuthCompleted = false;
    private boolean isIcVerified = false;
    private boolean isCardLocked = false;
    
    private byte authRetryCount = 0;
    private static final byte MAX_AUTH_TRIES = (byte) 5;

    
    private OwnerPIN pin;
    private DESKey secretKey;
    private Cipher decryptEngine;
    private Signature macEngine;
    private RandomData secureRandom;
    private byte[] randomChallenge;
    private byte[] calculatedMac;

    
    public static final short FILE_ID_MCU      = (short) 0xFF02;
    public static final short FILE_ID_FMS      = (short) 0xFF03;
    public static final short FILE_ID_ATTR     = (short) 0xFF04;
    public static final short FILE_ID_ACCOUNT  = (short) 0xFF05;

    private short selectedFile = (short) 0x0000;

    
    private static final byte MAX_FILES = (byte) 31;
    private static final short MAX_STORAGE_BYTES = (short) 2048;
    private byte nOfFiles = (byte) 0;

    private byte[] userFileManagement;
    private byte[] globalFileStorage; 
    private short[] fileOffsets;
    private short nextAvailableOffset = (short) 0;
    
    private byte[] ff03_fms_data;
    private byte[] ff02_mcu_data; 
    private byte[] ff04_attributes; 
    private byte[] ff05_account_data;

    
    public static final byte INS_START_SESSION   = (byte) 0x84;
    public static final byte INS_AUTHENTICATE    = (byte) 0x82;
    public static final byte INS_SUBMIT_CODE     = (byte) 0x20;
    public static final byte INS_CHANGE_PIN      = (byte) 0x24;
    public static final byte INS_SELECT_FILE     = (byte) 0xA4;
    public static final byte INS_READ_RECORD     = (byte) 0xB2;
    public static final byte INS_WRITE_RECORD    = (byte) 0xD2;
    public static final byte INS_CREDIT          = (byte) 0xE2;
    public static final byte INS_DEBIT           = (byte) 0xE6;
    public static final byte INS_REVOKE_DEBIT    = (byte) 0xE8;
    public static final byte INS_INQUIRE_ACCOUNT = (byte) 0xE4;
    public static final byte INS_CLEAR_CARD      = (byte) 0x30;

    private static final byte PIN_TRY_LIMIT = (byte) 3;
    private static final byte PIN_MAX_SIZE  = (byte) 8;

    protected Myapplet(byte[] bArray, short bOffset, byte bLength) {
        randomChallenge = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
        calculatedMac = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        
        secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        secretKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        byte[] keyData = new byte[16];
        secretKey.setKey(keyData, (short)0);

        decryptEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        macEngine = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);

        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        byte[] defaultPin = {1, 2, 3, 4};
        pin.update(defaultPin, (short)0, (byte)4);

        ff02_mcu_data = new byte[1];
        ff02_mcu_data[0] = (byte) 0x04;
        ff04_attributes = new byte[16]; 
        ff03_fms_data = new byte[16];
        byte[] icCode = {0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54};
        Util.arrayCopyNonAtomic(icCode, (short)0, ff03_fms_data, (short)0, (short)8);
        Util.arrayCopyNonAtomic(defaultPin, (short)0, ff03_fms_data, (short)8, (short)4);

        userFileManagement = new byte[(short) (MAX_FILES * 6)];
        globalFileStorage = new byte[MAX_STORAGE_BYTES];
        fileOffsets = new short[MAX_FILES];
        ff05_account_data = new byte[32];
        
        Util.setShort(ff05_account_data, (short)2, (short)1000);
        ff05_account_data[6] = calculateChecksum((short)0);
        
        
        Util.setShort(ff05_account_data, (short)16, (short)30000);


        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Myapplet(bArray, bOffset, bLength);
    }

    private byte calculateChecksum(short recOffset) {
        short sum = (short) (ff05_account_data[(short)(recOffset + 0)] & 0xFF);
        sum += (short) (ff05_account_data[(short)(recOffset + 1)] & 0xFF);
        sum += (short) (ff05_account_data[(short)(recOffset + 2)] & 0xFF);
        sum += (short) (ff05_account_data[(short)(recOffset + 3)] & 0xFF);
        sum += (short) (ff05_account_data[(short)(recOffset + 4)] & 0xFF);
        sum += (short) (ff05_account_data[(short)(recOffset + 5)] & 0xFF);
        sum += 1;
        return (byte) (sum & 0xFF);
    }

    private void checkAccess(byte accessCondition) {
        if (accessCondition == (byte) 0x00) return;
        if ((accessCondition & 0x01) != 0) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        if ((accessCondition & 0x80) != 0 && !isIcVerified) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if ((accessCondition & 0x40) != 0 && !pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if ((accessCondition & 0x02) != 0 && !isMutualAuthCompleted) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    private void startSession(APDU apdu) {
        sessionActive = true;
        isMutualAuthCompleted = false;
        authRetryCount = 0; 
        byte[] buffer = apdu.getBuffer();
        secureRandom.nextBytes(randomChallenge, (short)0, (short)8);
        Util.arrayCopyNonAtomic(randomChallenge, (short)0, buffer, (short)0, (short)8);
        apdu.setOutgoingAndSend((short)0, (short)8);
    }

    private void authenticate(APDU apdu) {
        if (isCardLocked) ISOException.throwIt((short)0x6283);
        if (!sessionActive) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        if (bytesRead != 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        byte[] zeroIv = {0,0,0,0,0,0,0,0};
        decryptEngine.init(secretKey, Cipher.MODE_DECRYPT, zeroIv, (short)0, (short)8);
        decryptEngine.doFinal(buffer, (short)ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);

        JCSystem.beginTransaction();
        authRetryCount = (byte)(authRetryCount + 1);
        if (authRetryCount >= MAX_AUTH_TRIES) isCardLocked = true;
        JCSystem.commitTransaction();

        if (Util.arrayCompare(buffer, (short)0, randomChallenge, (short)0, (short)8) != 0) { 
            isMutualAuthCompleted = false;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        JCSystem.beginTransaction();
        authRetryCount = (byte)0;
        JCSystem.commitTransaction();
        isMutualAuthCompleted = true; 
    }

    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();
        if (length <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        if (!pin.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)length)) {
            ISOException.throwIt((short)(0x63C0 | pin.getTriesRemaining()));
        }
    }

    private void verifyIC(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        if (bytesRead != (short)8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (Util.arrayCompare(buffer, (short)ISO7816.OFFSET_CDATA, ff03_fms_data, (short)0, (short)8) != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        this.isIcVerified = true; 
    }

    private void changePIN(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        if (bytesRead <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        pin.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)bytesRead);
    }

    private void selectFile(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (apdu.setIncomingAndReceive() < (short)2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short targetID = Util.getShort(buffer, (short)ISO7816.OFFSET_CDATA);

        if (targetID == FILE_ID_MCU || targetID == FILE_ID_FMS || targetID == FILE_ID_ATTR || targetID == FILE_ID_ACCOUNT) {
            selectedFile = targetID;
            return;
        }

        for (short i = 0; i < (short)nOfFiles; i++) {
            short offset = (short)(i * 6);
            short foundID = Util.getShort(userFileManagement, (short)(offset + 4));
            if (foundID == targetID) {
                selectedFile = targetID;
                ISOException.throwIt((short)(0x9100 | i)); 
            }
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private void readRecord(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recNo = (short)(buffer[ISO7816.OFFSET_P1] & (short)0xFF);

        if (selectedFile == FILE_ID_MCU) {
            Util.arrayCopyNonAtomic(ff02_mcu_data, (short)0, buffer, (short)0, (short)1);
            apdu.setOutgoingAndSend((short)0, (short)1);
        } else if (selectedFile == FILE_ID_FMS) {
            if (!isIcVerified) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            Util.arrayCopyNonAtomic(ff03_fms_data, (short)0, buffer, (short)0, (short)16);
            apdu.setOutgoingAndSend((short)0, (short)16);
        } else if (selectedFile == FILE_ID_ACCOUNT) {
            if (recNo >= 8) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            Util.arrayCopyNonAtomic(ff05_account_data, (short)(recNo * 4), buffer, (short)0, (short)4);
            apdu.setOutgoingAndSend((short)0, (short)4);
        } else {
            for (short i = 0; i < (short)nOfFiles; i++) {
                short offset = (short)(i * 6);
                if (Util.getShort(userFileManagement, (short)(offset + 4)) == selectedFile) {
                    checkAccess(userFileManagement[(short)(offset + 2)]);
                    short recLen = (short)(userFileManagement[offset] & (short)0xFF);
                    short absoluteDataOffset = (short)(fileOffsets[i] + (recNo * recLen)); 
                    Util.arrayCopyNonAtomic(globalFileStorage, absoluteDataOffset, buffer, (short)0, recLen);
                    apdu.setOutgoingAndSend((short)0, recLen);
                    return;
                }
            }
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void writeRecord(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recNo = (short)(buffer[ISO7816.OFFSET_P1] & (short)0xFF);
        short bytesRead = apdu.setIncomingAndReceive();
        
        if (bytesRead <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 

        if (selectedFile == FILE_ID_MCU || selectedFile == FILE_ID_ATTR || selectedFile == FILE_ID_ACCOUNT) {
            if (!isIcVerified) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        JCSystem.beginTransaction();
        if (selectedFile == FILE_ID_MCU) {
            nOfFiles = buffer[(short)(ISO7816.OFFSET_CDATA + 2)];
            nextAvailableOffset = 0;
        } else if (selectedFile == FILE_ID_ATTR) {
            Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, userFileManagement, (short)(recNo * 6), (short)6);
            short fileSize = (short)((buffer[ISO7816.OFFSET_CDATA] & 0xFF) * (buffer[(short)(ISO7816.OFFSET_CDATA+1)] & 0xFF));
            fileOffsets[recNo] = nextAvailableOffset;
            nextAvailableOffset += fileSize;
        } else if (selectedFile == FILE_ID_ACCOUNT) {
            Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, ff05_account_data, (short)(recNo * 4), bytesRead);
        } else {
           
            for (short i = 0; i < (short)nOfFiles; i++) {
                if (Util.getShort(userFileManagement, (short)(i * 6 + 4)) == selectedFile) {
                    checkAccess(userFileManagement[(short)(i * 6 + 3)]);
                    short recLen = (short)(userFileManagement[(short)(i * 6)] & 0xFF);
                    Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, globalFileStorage, (short)(fileOffsets[i] + (recNo * recLen)), bytesRead);
                    break;
                }
            }
        }
        JCSystem.commitTransaction();
    }
    private void updateAccount(APDU apdu, boolean isCredit) {
        if (selectedFile != FILE_ID_ACCOUNT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isMutualAuthCompleted) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte expectedChecksum = calculateChecksum((short)0);
        if (expectedChecksum != ff05_account_data[6]) {
            ISOException.throwIt((short)0x69F0); 
        }

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        if (bytesRead < (short)11) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short macOffset  = ISO7816.OFFSET_CDATA;
        short dataOffset = (short)(ISO7816.OFFSET_CDATA + 4); 
        short dataLength = (short)(bytesRead - 4);

        macEngine.init(secretKey, Signature.MODE_SIGN);
        macEngine.sign(buffer, dataOffset, dataLength, calculatedMac, (short)0);

        if (Util.arrayCompare(buffer, macOffset, calculatedMac, (short)0, (short)4) != (byte)0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short transactionAmount = Util.getShort(buffer, (short)(dataOffset + 1));
        short currentBalance = Util.getShort(ff05_account_data, (short)2);
        short newBalance;

        if (isCredit) {
            short maxBalance = Util.getShort(ff05_account_data, (short)16); 
            if ((short)(currentBalance + transactionAmount) < currentBalance) {
                ISOException.throwIt((short)0x6B20); 
            }
            newBalance = (short)(currentBalance + transactionAmount);
            if (newBalance > maxBalance) {
                ISOException.throwIt((short)0x6B20); 
            }
        } else {
            if (transactionAmount <= 0 || transactionAmount > currentBalance) {
                ISOException.throwIt((short)0x6B20); 
            }
            newBalance = (short)(currentBalance - transactionAmount);
        }

        JCSystem.beginTransaction();
        
        Util.arrayCopy(ff05_account_data, (short)0, ff05_account_data, (short)8, (short)8);
        ff05_account_data[14] = calculateChecksum((short)8);

        ff05_account_data[0] = isCredit ? (byte)0x03 : (byte)0x01;
        Util.setShort(ff05_account_data, (short)2, newBalance);

        short ttrefSourceOffset = (short)(dataOffset + 3);
        short ttrefTargetOffset = isCredit ? (short)24 : (short)28; 
        Util.arrayCopy(buffer, ttrefSourceOffset, ff05_account_data, ttrefTargetOffset, (short)4);

        short atc = Util.getShort(ff05_account_data, (short)4);
        Util.setShort(ff05_account_data, (short)4, (short)(atc + 1));

        ff05_account_data[6] = calculateChecksum((short)0);

        JCSystem.commitTransaction();
    }



    private void revokeDebit(APDU apdu) {
        if (selectedFile != FILE_ID_ACCOUNT || !isMutualAuthCompleted) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        JCSystem.beginTransaction();
        Util.arrayCopy(ff05_account_data, (short)8, ff05_account_data, (short)0, (short)8);
        ff05_account_data[0] = (byte) 0x02;
        Util.setShort(ff05_account_data, (short)4, (short)(Util.getShort(ff05_account_data, (short)4) + 1));
        ff05_account_data[6] = calculateChecksum((short)0);
        JCSystem.commitTransaction();
    }
    
    private void inquireAccount(APDU apdu) {
        if (selectedFile != FILE_ID_ACCOUNT) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        Util.arrayCopyNonAtomic(ff05_account_data, (short)0, apdu.getBuffer(), (short)0, (short)32);
        apdu.setOutgoingAndSend((short)0, (short)32);
    }

    private void clearCard(APDU apdu) {
        if (!isIcVerified) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        JCSystem.beginTransaction();
        
        byte[] defaultPin = {1, 2, 3, 4};
        pin.update(defaultPin, (short)0, (byte)4);
        pin.reset(); 
        
        Util.arrayFillNonAtomic(ff05_account_data, (short)0, (short)32, (byte)0);
        
        Util.setShort(ff05_account_data, (short)2, (short)1000); 
        
        Util.setShort(ff05_account_data, (short)16, (short)30000);
        
        ff05_account_data[6] = calculateChecksum((short)0);
        
        JCSystem.commitTransaction();

        isMutualAuthCompleted = false;
        isIcVerified = false;
        sessionActive = false;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != (byte)0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_START_SESSION:   startSession(apdu); break;
            case INS_AUTHENTICATE:    authenticate(apdu); break;
            case INS_SUBMIT_CODE:
                if (buffer[ISO7816.OFFSET_P1] == (byte)0x06) verifyPIN(apdu);
                else if (buffer[ISO7816.OFFSET_P1] == (byte)0x07) verifyIC(apdu);
                else ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                break;
            case INS_CHANGE_PIN:      changePIN(apdu); break;
            case INS_SELECT_FILE:     selectFile(apdu); break;
            case INS_READ_RECORD:     readRecord(apdu); break;
            case INS_WRITE_RECORD:    writeRecord(apdu); break;
            case INS_CREDIT:          updateAccount(apdu, true); break;
            case INS_DEBIT:           updateAccount(apdu, false); break;
            case INS_REVOKE_DEBIT:    revokeDebit(apdu); break;
            case INS_INQUIRE_ACCOUNT: inquireAccount(apdu); break;
            case INS_CLEAR_CARD:      clearCard(apdu); break;
            default:                  ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}