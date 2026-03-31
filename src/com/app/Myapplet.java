package com.app;

import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.KeyBuilder;
import javacard.security.DESKey;
import javacardx.crypto.Cipher;

public class Myapplet extends Applet {
    private boolean sessionActive = false;
    private boolean isAuthenticated = false;
    private boolean isCardLocked = false;
    private byte authRetryCount = 0;
    private static final byte MAX_AUTH_TRIES = (byte) 5;

    private OwnerPIN pin;
    private DESKey secretKey;
    private Cipher decryptEngine;
    private RandomData secureRandom;
    private byte[] randomChallenge;

    public static final short FILE_ID_ATTR = (short) 0xFF04;
    public static final short FILE_ID_MCU  = (short) 0xFF02;
    public static final short FILE_ID_FMS  = (short) 0xFF03;
    public static final short FILE_ID_BALANCE = (short) 0xEE01;

    private short selectedFile = (short) 0x0000;

    private static final byte MAX_FILES = (byte) 31;
    private byte nOfFiles = (byte) 0;

    private byte[] userFileManagement;
    private Object[] fileDataStorage;

    private byte[] ff02_mcu_data;
    private byte[] ff03_fms_data;
    private byte[] ff04_attributes = { (byte)0x03, (byte)0x03 };
    private byte[] balanceData;

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
    public static final byte INS_CLEAR_CARD      = (byte) 0x30;

    private static final byte PIN_TRY_LIMIT = (byte) 3;
    private static final byte PIN_MAX_SIZE  = (byte) 8;

    protected Myapplet(byte[] bArray, short bOffset, byte bLength) {

        randomChallenge = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
        secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        secretKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
        byte[] keyData = new byte[16];
        secretKey.setKey(keyData, (short)0);

        decryptEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);

        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        byte[] defaultPin = {1, 2, 3, 4};
        pin.update(defaultPin, (short)0, (byte)4);

        ff02_mcu_data = new byte[1];
        ff02_mcu_data[0] = (byte) 0x04;

        ff03_fms_data = new byte[16];
        byte[] icCode = {0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54};

        Util.arrayCopyNonAtomic(icCode, (short)0, ff03_fms_data, (short)0, (short)8);
        Util.arrayCopyNonAtomic(defaultPin, (short)0, ff03_fms_data, (short)8, (short)4);

        balanceData = new byte[2];
        Util.setShort(balanceData, (short)0, (short)1000);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Myapplet(bArray, bOffset, bLength);
    }

    private void checkAccess(byte accessCondition) {
        switch (accessCondition) {
            case (byte) 0x00: break;
            case (byte) 0x01:
                if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
            case (byte) 0x02:
                if (!isAuthenticated) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
            case (byte) 0x03:
                if (!pin.isValidated() || !isAuthenticated) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
            default: ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void startSession(APDU apdu) {
        sessionActive = true;
        isAuthenticated = false;
        byte[] buffer = apdu.getBuffer();
        secureRandom.generateData(randomChallenge, (short)0, (short)8);
        Util.arrayCopyNonAtomic(randomChallenge, (short)0, buffer, (short)0, (short)8);
        apdu.setOutgoingAndSend((short)0, (short)8);
    }

    private void authenticate(APDU apdu) {
        if (isCardLocked) ISOException.throwIt((short)0x6283);
        if (!sessionActive) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        byte[] zeroIv = {0,0,0,0,0,0,0,0};
        decryptEngine.init(secretKey, Cipher.MODE_DECRYPT, zeroIv, (short)0, (short)8);
        decryptEngine.doFinal(buffer, (short)ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);

        if (Util.arrayCompare(buffer, (short)0, randomChallenge, (short)0, (short)8) != (byte)0) {
            authRetryCount = (byte)(authRetryCount + 1);
            if (authRetryCount >= MAX_AUTH_TRIES) isCardLocked = true;
            isAuthenticated = false;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        authRetryCount = (byte)0;
        isAuthenticated = true;
    }

    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();
        if (!pin.check(buffer, (short)ISO7816.OFFSET_CDATA, (byte)length)) {
            ISOException.throwIt((short)(0x63C0 | pin.getTriesRemaining()));
        }
    }

    private void verifyIC(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        if (bytesRead != (short)8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (Util.arrayCompare(buffer, (short)ISO7816.OFFSET_CDATA, ff03_fms_data, (short)0, (short)8) != (byte)0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        this.isAuthenticated = true;
    }

    private void changePIN(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        pin.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)bytesRead);
    }

    private void selectFile(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (apdu.setIncomingAndReceive() < (short)2) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short targetID = Util.getShort(buffer, (short)ISO7816.OFFSET_CDATA);

        if (targetID == FILE_ID_MCU || targetID == FILE_ID_FMS || targetID == FILE_ID_ATTR || targetID == FILE_ID_BALANCE) {
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
            checkAccess((byte)0x02);
            Util.arrayCopyNonAtomic(ff03_fms_data, (short)0, buffer, (short)0, (short)16);
            apdu.setOutgoingAndSend((short)0, (short)16);

        } else if (selectedFile == FILE_ID_ATTR) {
            Util.arrayCopyNonAtomic(ff04_attributes, (short)0, buffer, (short)0, (short)2);
            apdu.setOutgoingAndSend((short)0, (short)2);

        } else if (selectedFile == FILE_ID_BALANCE) {
            checkAccess(ff04_attributes[0]);
            Util.arrayCopyNonAtomic(balanceData, (short)0, buffer, (short)0, (short)2);
            apdu.setOutgoingAndSend((short)0, (short)2);

        } else {
            for (short i = 0; i < (short)nOfFiles; i++) {
                short offset = (short)(i * 6);

                if (Util.getShort(userFileManagement, (short)(offset + 4)) == selectedFile) {

                    checkAccess(userFileManagement[(short)(offset + 2)]);

                    short recLen = (short)(userFileManagement[offset] & (short)0xFF);
                    short dataOffset = (short)(recNo * recLen);

                    byte[] targetFile = (byte[]) fileDataStorage[i];

                    Util.arrayCopyNonAtomic(targetFile, dataOffset, buffer, (short)0, recLen);
                    apdu.setOutgoingAndSend((short)0, recLen);
                    return;
                }
            }
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void writeRecord(APDU apdu) {
        if (!isAuthenticated) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buffer = apdu.getBuffer();
        short recNo = (short)(buffer[ISO7816.OFFSET_P1] & (short)0xFF);
        short bytesRead = apdu.setIncomingAndReceive();

        JCSystem.beginTransaction();

        if (selectedFile == FILE_ID_MCU) {

            nOfFiles = buffer[(short)(ISO7816.OFFSET_CDATA + 2)];

            if (nOfFiles > MAX_FILES) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

            userFileManagement = new byte[(short)((short)nOfFiles * (short)6)];
            fileDataStorage = new Object[(short)nOfFiles];

        } else if (selectedFile == FILE_ID_ATTR) {

            Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA,
                    userFileManagement, (short)(recNo * 6), (short)6);

            short recLen = (short)(buffer[(short)ISO7816.OFFSET_CDATA] & (short)0xFF);
            short numRecs = (short)(buffer[(short)(ISO7816.OFFSET_CDATA + 1)] & (short)0xFF);

            fileDataStorage[recNo] = new byte[(short)(recLen * numRecs)];

        } else {

            boolean fileFound = false;

            for (short i = 0; i < (short)nOfFiles; i++) {

                short offset = (short)(i * 6);

                if (Util.getShort(userFileManagement, (short)(offset + 4)) == selectedFile) {

                    fileFound = true;

                    checkAccess(userFileManagement[(short)(offset + 3)]);

                    short recLen = (short)(userFileManagement[offset] & (short)0xFF);
                    short dataOffset = (short)(recNo * recLen);

                    byte[] targetFile = (byte[]) fileDataStorage[i];

                    Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA,
                            targetFile, dataOffset, bytesRead);

                    break;
                }
            }

            if (!fileFound) {
                JCSystem.abortTransaction();
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        }

        JCSystem.commitTransaction();
    }

    private void updateAccount(APDU apdu, boolean isCredit) {

        if (selectedFile != FILE_ID_BALANCE)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        checkAccess(ff04_attributes[1]);

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short transactionAmount = Util.getShort(buffer, (short)ISO7816.OFFSET_CDATA);
        short currentBalance = Util.getShort(balanceData, (short)0);
        short newBalance;

        if (isCredit) {
            newBalance = (short)(currentBalance + transactionAmount);
            if (newBalance < currentBalance) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        } else {
            if (transactionAmount > currentBalance) ISOException.throwIt((short)0x6A80);
            newBalance = (short)(currentBalance - transactionAmount);
        }

        JCSystem.beginTransaction();
        Util.setShort(balanceData, (short)0, newBalance);
        JCSystem.commitTransaction();
    }

    private void revokeDebit(APDU apdu) {

        if (!isAuthenticated)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        if (selectedFile != FILE_ID_BALANCE)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short amountToRevoke = Util.getShort(buffer, (short)ISO7816.OFFSET_CDATA);
        short currentBalance = Util.getShort(balanceData, (short)0);

        short newBalance = (short)(currentBalance + amountToRevoke);

        if (newBalance < currentBalance)
            ISOException.throwIt(ISO7816.SW_FILE_FULL);

        JCSystem.beginTransaction();
        Util.setShort(balanceData, (short)0, newBalance);
        JCSystem.commitTransaction();
    }

    private void clearCard(APDU apdu) {

        if (!isAuthenticated)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        JCSystem.beginTransaction();

        Util.arrayFillNonAtomic(balanceData, (short)0, (short)2, (byte)0);

        byte[] defaultPin = {1, 2, 3, 4};
        pin.update(defaultPin, (short)0, (byte)4);
        pin.reset();

        nOfFiles = (byte)0;
        userFileManagement = null;
        fileDataStorage = null;

        isCardLocked = false;
        authRetryCount = (byte)0;

        JCSystem.commitTransaction();

        isAuthenticated = false;
        sessionActive = false;
    }

    public void process(APDU apdu) {

        if (selectingApplet()) {
            sessionActive = false;
            isAuthenticated = false;
            selectedFile = (short)0x0000;
            return;
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != (byte)0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {

            case INS_START_SESSION: startSession(apdu); break;
            case INS_AUTHENTICATE:  authenticate(apdu); break;

            case INS_SUBMIT_CODE:
                byte codeRef = buffer[ISO7816.OFFSET_P1];

                if (codeRef == (byte)0x06) verifyPIN(apdu);
                else if (codeRef == (byte)0x07) verifyIC(apdu);
                else ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                break;

            case INS_CHANGE_PIN:    changePIN(apdu); break;
            case INS_SELECT_FILE:   selectFile(apdu); break;
            case INS_READ_RECORD:   readRecord(apdu); break;
            case INS_WRITE_RECORD:  writeRecord(apdu); break;
            case INS_CREDIT:        updateAccount(apdu, true); break;
            case INS_DEBIT:         updateAccount(apdu, false); break;
            case INS_REVOKE_DEBIT:  revokeDebit(apdu); break;
            case INS_CLEAR_CARD:    clearCard(apdu); break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}