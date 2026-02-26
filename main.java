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
class MSC_ScanNotFound extends RuntimeException { public MSC_ScanNotFound() { super("MSC_ScanNotFound"); } }
class MSC_InvalidRiskTier extends RuntimeException { public MSC_InvalidRiskTier() { super("MSC_InvalidRiskTier"); } }
class MSC_AlreadyWhitelisted extends RuntimeException { public MSC_AlreadyWhitelisted() { super("MSC_AlreadyWhitelisted"); } }
class MSC_NotWhitelisted extends RuntimeException { public MSC_NotWhitelisted() { super("MSC_NotWhitelisted"); } }
class MSC_AlreadyBlacklisted extends RuntimeException { public MSC_AlreadyBlacklisted() { super("MSC_AlreadyBlacklisted"); } }
class MSC_NotBlacklisted extends RuntimeException { public MSC_NotBlacklisted() { super("MSC_NotBlacklisted"); } }
class MSC_ArrayLengthMismatch extends RuntimeException { public MSC_ArrayLengthMismatch() { super("MSC_ArrayLengthMismatch"); } }
class MSC_BatchTooLarge extends RuntimeException { public MSC_BatchTooLarge() { super("MSC_BatchTooLarge"); } }
class MSC_MaxScansReached extends RuntimeException { public MSC_MaxScansReached() { super("MSC_MaxScansReached"); } }
class MSC_InvalidCategory extends RuntimeException { public MSC_InvalidCategory() { super("MSC_InvalidCategory"); } }
class MSC_CategoryLimitReached extends RuntimeException { public MSC_CategoryLimitReached() { super("MSC_CategoryLimitReached"); } }
class MSC_ZeroToken extends RuntimeException { public MSC_ZeroToken() { super("MSC_ZeroToken"); } }
class MSC_ReporterAlreadyRegistered extends RuntimeException { public MSC_ReporterAlreadyRegistered() { super("MSC_ReporterAlreadyRegistered"); } }
class MSC_ReporterNotRegistered extends RuntimeException { public MSC_ReporterNotRegistered() { super("MSC_ReporterNotRegistered"); } }

// ============== DTOs ==============

final class ScanInfoDTO {
    final String scanId;
    final String target;
    final int riskTier;
    final String flagsHash;
    final String reporter;
    final long atBlock;
    final boolean exists;

    ScanInfoDTO(String scanId, String target, int riskTier, String flagsHash, String reporter, long atBlock, boolean exists) {
        this.scanId = scanId;
        this.target = target;
        this.riskTier = riskTier;
        this.flagsHash = flagsHash;
        this.reporter = reporter;
        this.atBlock = atBlock;
        this.exists = exists;
    }
}

final class TokenInfoDTO {
    final String tokenScanId;
    final String tokenAddress;
    final String symbolHash;
    final boolean registered;

    TokenInfoDTO(String tokenScanId, String tokenAddress, String symbolHash, boolean registered) {
        this.tokenScanId = tokenScanId;
        this.tokenAddress = tokenAddress;
        this.symbolHash = symbolHash;
        this.registered = registered;
    }
}

final class AddressStatusDTO {
    final boolean whitelisted;
    final boolean blacklisted;
    final int scanCount;

    AddressStatusDTO(boolean whitelisted, boolean blacklisted, int scanCount) {
        this.whitelisted = whitelisted;
        this.blacklisted = blacklisted;
        this.scanCount = scanCount;
    }
}

final class GlobalStatsDTO {
    final int totalScans;
    final int totalTokens;
    final int totalReporters;
    final int whitelistLen;
    final int blacklistLen;
    final long vaultBalance;

    GlobalStatsDTO(int totalScans, int totalTokens, int totalReporters, int whitelistLen, int blacklistLen, long vaultBalance) {
        this.totalScans = totalScans;
        this.totalTokens = totalTokens;
        this.totalReporters = totalReporters;
        this.whitelistLen = whitelistLen;
        this.blacklistLen = blacklistLen;
        this.vaultBalance = vaultBalance;
    }
}

// ============== Engine ==============

public final class MonsterScanEngine {
    private final String scannerKeeper;
    private final String reportVault;
    private final long deployBlock;
    private long currentBlock;
    private final Map<String, ScanInfoDTO> scans = new HashMap<>();
    private final List<String> scanIds = new ArrayList<>();
    private final Map<String, List<String>> targetScanIds = new HashMap<>();
    private final Set<String> whitelist = new HashSet<>();
    private final Set<String> blacklist = new HashSet<>();
    private final List<String> whitelistArr = new ArrayList<>();
    private final List<String> blacklistArr = new ArrayList<>();
    private final Set<String> reporters = new HashSet<>();
    private final Map<Integer, Long> riskThreshold = new HashMap<>();
    private final Map<String, String> tokenAddress = new HashMap<>();
