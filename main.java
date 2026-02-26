/*
 * MSJ — MonsterScan Java. Single combined module for crypto scanner logic.
 * On-chain registry for token and address scans; reporters submit risk scores and flags.
 * All outputs in one file: constants, exceptions, DTOs, engine, API handlers, validation.
 */

package contracts;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

// ============== Constants ==============

public final class MSJ {
    private MSJ() {}

    public static final int MSC_MAX_RISK_TIER = 10;
    public static final int MSC_MAX_SCANS = 50_000;
    public static final int MSC_BATCH_LIMIT = 64;
    public static final int MSC_VIEW_BATCH = 96;
    public static final int MSC_MAX_CATEGORIES = 16;
    public static final String MSC_SCAN_DOMAIN = sha256Hex("MonsterScan.MSC_SCAN_DOMAIN");
    public static final String MSC_REPORTER_ROLE = sha256Hex("MonsterScan.MSC_REPORTER_ROLE");
    public static final String MSC_TOKEN_NAMESPACE = sha256Hex("MonsterScan.MSC_TOKEN_NAMESPACE");

    public static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

// ============== Exceptions ==============

class MSC_ZeroAddress extends RuntimeException { public MSC_ZeroAddress() { super("MSC_ZeroAddress"); } }
class MSC_ZeroScanId extends RuntimeException { public MSC_ZeroScanId() { super("MSC_ZeroScanId"); } }
class MSC_NotKeeper extends RuntimeException { public MSC_NotKeeper() { super("MSC_NotKeeper"); } }
class MSC_NotReporter extends RuntimeException { public MSC_NotReporter() { super("MSC_NotReporter"); } }
class MSC_NotVault extends RuntimeException { public MSC_NotVault() { super("MSC_NotVault"); } }
class MSC_ScanAlreadyExists extends RuntimeException { public MSC_ScanAlreadyExists() { super("MSC_ScanAlreadyExists"); } }
